/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cxl_exp_backend.h"
#include "common/nixl_log.h"
#include <numaif.h>
#include <numa.h>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sys/types.h>

nixl_b_params_t
get_cxl_exp_backend_options() {
    nixl_b_params_t params;
    params["numa_policy"] = "bind"; // Options: bind, preferred, interleave
    params["force_cxl_device"] = ""; // Empty means auto-detect
    return params;
}

/**
 * Lightweight reader for optional sysfs u64 attributes.
 * @return true and populates @out on success, false if the file is missing
 *         or cannot be parsed.  No logging is emitted – callers decide.
 */
static bool
readSysfsU64(const std::string &path, uint64_t &out) {
    std::ifstream f(path);
    if (!f.good()) {
        return false;
    }
    f >> out;
    return f.good();
}

nixlCxlExpEngine::nixlCxlExpEngine(const nixlBackendInitParams *init_params)
    : nixlBackendEngine(init_params),
      agent_name_(init_params->localAgent) {

    // Direct console output that will bypass any output capture
    FILE *output = fopen("/dev/tty", "w");
    if (output) {
        fprintf(output, "\n==== CXL PLUGIN CONSTRUCTOR CALLED (TTY OUTPUT) ====\n");
        fclose(output);
    }

    // Create a marker file with detailed information
    FILE *marker_file = fopen("/tmp/cxl_plugin_initialized", "w");
    if (marker_file) {
        time_t now = time(NULL);
        fprintf(marker_file, "Constructor called at: %s\n", ctime(&now));
        fprintf(marker_file, "Agent name: %s\n", init_params->localAgent.c_str());
        fprintf(marker_file, "Type: %s\n", init_params->type.c_str());
        fprintf(marker_file, "Process PID: %d\n", getpid());
        fclose(marker_file);
    }

    // Keep the existing log message which might be captured in logs
    NIXL_INFO << "Initializing CXL Experimental Backend";

    // Check if NUMA library is available
    if (numa_available() < 0) {
        NIXL_ERROR << "NUMA library not available";
        this->initErr = true;
        return;
    }

    // Initialize NUMA topology
    if (!discoverCXLNodes()) {
        NIXL_ERROR << "Failed to discover CXL NUMA nodes";
        this->initErr = true;
        return;
    }

    if (cxl_nodes_.empty()) {
        NIXL_ERROR << "No CXL devices found in system";
        this->initErr = true;
        return;
    }

    NIXL_INFO << "Found " << cxl_nodes_.size() << " CXL NUMA nodes";
    for (const auto &[node_id, bandwidth] : cxl_nodes_) {
        NIXL_INFO << "  Node " << node_id << " with bandwidth " << bandwidth << " MB/s";
    }

    initialized_ = true;
}

nixlCxlExpEngine::~nixlCxlExpEngine() {
    // Clean up resources if needed
}

nixl_mem_list_t
nixlCxlExpEngine::getSupportedMems() const {
    return {DRAM_SEG, CXL_EXP_SEG};
}

bool
nixlCxlExpEngine::checkSNC() {
    // Check for Sub-NUMA Clustering if relevant for your system
    // Placeholder implementation
    return false;
}

bool
nixlCxlExpEngine::discoverCXLNodes() {
    // Try direct CXL sysfs path discovery
    const std::string cxl_path = "/sys/bus/cxl/devices";
    NIXL_INFO << "Checking for CXL devices at path: " << cxl_path;

    DIR *dir = opendir(cxl_path.c_str());
    if (!dir) {
        NIXL_WARN << "CXL sysfs path \"" << cxl_path
                  << "\" not found or cannot be opened (errno=" << errno << " - " << strerror(errno)
                  << "). "
                  << "CXL discovery aborted.";
        return false;
    }

    NIXL_INFO << "Successfully opened CXL path: " << cxl_path;

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        NIXL_DEBUG << "Found directory entry: " << name;

        // Look for memory devices (mem*) or regions
        if (name != "." && name != ".." &&
            ((name.find("mem") == 0) || (name.find("region") == 0))) {
            NIXL_INFO << "Found potential CXL device/region: " << name;

            // ---------- Resolve NUMA node for this CXL endpoint ----------
            const std::vector<std::string> cand = {
                cxl_path + "/" + name + "/numa_node",
                cxl_path + "/" + name + "/access0/numa_node",
                cxl_path + "/" + name + "/target_node",
            };

            uint64_t node_val = 0;
            bool have_id = false;
            for (const auto &p : cand) {
                if (readSysfsU64(p, node_val)) {
                    have_id = true;
                    break;
                }
            }
            if (!have_id) {
                NIXL_DEBUG << "No NUMA id attribute found for " << name << "; skipping";
                continue;
            }
            const int node_id = static_cast<int>(node_val);
            if (node_id < 0) {
                NIXL_DEBUG << "Negative NUMA id for " << name << "; skipping";
                continue;
            }

            // Create node info structure and read real values
            CXLNodeInfo node_info{};
            node_info.read_bandwidth_mbps = 0;
            node_info.write_bandwidth_mbps = 0;
            node_info.read_latency_ns = 0;
            node_info.write_latency_ns = 0;

            // Check for region-specific bandwidth and latency files
            std::string access_path = cxl_path + "/" + name;
            if (name.find("region") == 0) {
                access_path += "/access0";
            }
            NIXL_DEBUG << "Looking for bandwidth/latency info at: " << access_path;

            // Try to read bandwidth and latency directly from the device
            std::string read_bw_path = access_path + "/read_bandwidth";
            std::string write_bw_path = access_path + "/write_bandwidth";
            std::string read_lat_path = access_path + "/read_latency";
            std::string write_lat_path = access_path + "/write_latency";

            NIXL_DEBUG << "Checking read bandwidth at: " << read_bw_path;
            uint64_t read_bw = readUint64FromFile(read_bw_path);
            NIXL_DEBUG << "Checking write bandwidth at: " << write_bw_path;
            uint64_t write_bw = readUint64FromFile(write_bw_path);
            NIXL_DEBUG << "Checking read latency at: " << read_lat_path;
            uint64_t read_lat = readUint64FromFile(read_lat_path);
            NIXL_DEBUG << "Checking write latency at: " << write_lat_path;
            uint64_t write_lat = readUint64FromFile(write_lat_path);

            NIXL_INFO << "Read BW: " << read_bw << ", Write BW: " << write_bw
                      << ", Read latency: " << read_lat << ", Write latency: " << write_lat;

            if (read_bw > 0) {
                node_info.read_bandwidth_mbps = read_bw / 1024; // Convert KiB/s to MiB/s
                NIXL_DEBUG << "Set read_bandwidth_mbps = " << node_info.read_bandwidth_mbps;
            }
            if (write_bw > 0) {
                node_info.write_bandwidth_mbps = write_bw / 1024;
                NIXL_DEBUG << "Set write_bandwidth_mbps = " << node_info.write_bandwidth_mbps;
            }
            if (read_lat > 0) {
                node_info.read_latency_ns = read_lat;
                NIXL_DEBUG << "Set read_latency_ns = " << node_info.read_latency_ns;
            }
            if (write_lat > 0) {
                node_info.write_latency_ns = write_lat;
                NIXL_DEBUG << "Set write_latency_ns = " << node_info.write_latency_ns;
            }

            // If direct reads failed, try our comprehensive performance metric reader
            if (node_info.read_bandwidth_mbps == 0 || node_info.read_latency_ns == 0) {
                NIXL_INFO << "Direct metrics reading failed, trying performance metric "
                             "reader...";
                readCXLPerformanceMetrics(node_id, node_info);
            }

            NIXL_INFO << "Discovered CXL device " << name << " on NUMA node " << node_id;
            NIXL_INFO << "  Read BW: " << node_info.read_bandwidth_mbps
                      << " MB/s, Write BW: " << node_info.write_bandwidth_mbps << " MB/s";
            NIXL_INFO << "  Read latency: " << node_info.read_latency_ns
                      << " ns, Write latency: " << node_info.write_latency_ns << " ns";

            cxl_node_info_.emplace(node_id, node_info);
            cxl_nodes_.emplace(node_id, node_info.read_bandwidth_mbps);
            NIXL_INFO << "Added node " << node_id << " to cxl_nodes_ and cxl_node_info_ maps";
        }
    }
    closedir(dir);
    NIXL_INFO << "Finished reading CXL device directory";

    if (!cxl_nodes_.empty()) {
        NIXL_INFO << "CXL nodes found via direct sysfs path: " << cxl_nodes_.size() << " nodes";
        return true;
    } else {
        NIXL_WARN << "discoverCXLNodes(): no nodes via /sys/bus/cxl/devices - "
                  << "ensure the kernel CXL driver is loaded and that "
                  << "`/sys/bus/cxl/devices/*/numa_node` exists.";
    }

    return false;
}

// Helper method to check if a file exists
bool
nixlCxlExpEngine::fileExists(const std::string &path) {
    std::ifstream file(path);
    return file.good();
}

// Implementation of the missing function to read uint64_t values from files
uint64_t
nixlCxlExpEngine::readUint64FromFile(const std::string &path) {
    uint64_t value = 0;

    // Check if file exists before attempting to read
    if (!fileExists(path)) {
        return 0;
    }

    try {
        std::ifstream file(path);
        if (file.good()) {
            file >> value;
        }
    }
    catch (const std::exception &e) {
        NIXL_WARN << "Error reading from file " << path << ": " << e.what();
    }

    return value;
}

// Read real CXL performance metrics from sysfs or other sources
void
nixlCxlExpEngine::readCXLPerformanceMetrics(int node_id, CXLNodeInfo &node_info) {
    // Base path for node-specific information
    std::string node_path = "/sys/devices/system/node/node" + std::to_string(node_id);

    // Look for CXL-specific sysfs entries
    std::string cxl_base_path = "/sys/bus/cxl/devices/";

    // First try to find CXL device directories
    std::vector<std::string> cxl_devices;
    DIR *dir = opendir(cxl_base_path.c_str());
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string name = entry->d_name;
            if (name != "." && name != ".." &&
                (name.find("mem") == 0 || name.find("decoder") == 0)) {
                cxl_devices.push_back(cxl_base_path + name);
            }
        }
        closedir(dir);
    }

    // Check if we found any CXL devices
    if (!cxl_devices.empty()) {
        NIXL_INFO << "Found " << cxl_devices.size() << " CXL devices";

        // Try to read performance metrics from each device
        for (const auto &device_path : cxl_devices) {
            // Try to read bandwidth from device info
            std::string bw_path = device_path + "/bandwidth";
            if (fileExists(bw_path)) {
                std::ifstream bw_file(bw_path);
                uint64_t bw_value;
                if (bw_file >> bw_value) {
                    // Assume this is in MB/s
                    node_info.read_bandwidth_mbps = bw_value;
                    node_info.write_bandwidth_mbps = bw_value * 0.9; // Typically write is slower
                    NIXL_INFO << "Read bandwidth from " << bw_path << ": " << bw_value << " MB/s";
                }
            }

            // Try to read latency from device info
            std::string lat_path = device_path + "/latency";
            if (fileExists(lat_path)) {
                std::ifstream lat_file(lat_path);
                uint32_t lat_value;
                if (lat_file >> lat_value) {
                    // Assume this is in nanoseconds
                    node_info.read_latency_ns = lat_value;
                    node_info.write_latency_ns =
                        lat_value * 1.2; // Typically write has higher latency
                    NIXL_INFO << "Read latency from " << lat_path << ": " << lat_value << " ns";
                }
            }
        }
    } else {
        NIXL_WARN << "No CXL devices found in sysfs. Using estimated values.";

        // If we can't find explicit CXL devices, try to estimate from memory latency
        if (fileExists("/sys/devices/system/cpu/cpu0/acpi_cppc/highest_perf")) {
            // Read CPU frequency to estimate CXL latency
            std::ifstream freq_file("/sys/devices/system/cpu/cpu0/acpi_cppc/highest_perf");
            uint64_t cpu_freq;
            if (freq_file >> cpu_freq) {
                // Convert to a rough estimate of latency
                uint32_t base_latency = 75; // Base latency estimate
                node_info.read_latency_ns = base_latency + 20; // Adjust based on node distance
                node_info.write_latency_ns = node_info.read_latency_ns * 1.2;

                NIXL_INFO << "Estimated CXL latency based on CPU performance: "
                          << node_info.read_latency_ns << " ns";
            }
        }

        // Try to estimate bandwidth from memory node information
        if (fileExists(node_path + "/meminfo")) {
            // This is a very rough estimate based on node characteristics
            long long node_size = numa_node_size64(node_id, nullptr);
            if (node_size > 0) {
                // Rough bandwidth estimate based on node size (larger nodes might be slower)
                double size_gb = node_size / (1024.0 * 1024.0 * 1024.0);
                node_info.read_bandwidth_mbps = 16000 - (size_gb > 100 ? 4000 : 0);
                node_info.write_bandwidth_mbps = node_info.read_bandwidth_mbps * 0.9;

                NIXL_INFO << "Estimated CXL bandwidth based on memory size: "
                          << node_info.read_bandwidth_mbps << " MB/s";
            }
        }
    }

    /* Apply conservative defaults if sysfs did not provide numbers */
    if (node_info.read_bandwidth_mbps == 0) {
        node_info.read_bandwidth_mbps = 30000; // 30 GB/s ~= Gen‑5 x8 practical
        node_info.write_bandwidth_mbps = 27000; // 10 % penalty for writes
    }
    if (node_info.read_latency_ns == 0) {
        node_info.read_latency_ns = 250; // ns
        node_info.write_latency_ns = 300; // ns
    }
}

nixl_status_t
nixlCxlExpEngine::registerMem(const nixlBlobDesc &mem,
                              const nixl_mem_t &nixl_mem,
                              nixlBackendMD *&out) {
    if (!initialized_) {
        return NIXL_ERR_BACKEND;
    }

    if (nixl_mem != DRAM_SEG && nixl_mem != CXL_EXP_SEG) {
        NIXL_ERROR << "CXL backend supports only DRAM_SEG or CXL_EXP_SEG";
        return NIXL_ERR_INVALID_PARAM;
    }

    auto metadata = new nixlCxlExpMetadata();

    // Try to determine which NUMA node this memory belongs to
    void *addr = reinterpret_cast<void *>(mem.addr);
    int status = -1;
    int node_result = -1;

    status = get_mempolicy(&node_result, nullptr, 0, addr, MPOL_F_NODE | MPOL_F_ADDR);

    if (status == 0 && node_result >= 0) {
        metadata->numa_node_id = node_result;

        // Check if this is a CXL node
        if (cxl_nodes_.find(node_result) != cxl_nodes_.end()) {
            NIXL_INFO << "Registered memory is on CXL NUMA node " << node_result;
        } else {
            NIXL_INFO << "Registered memory is on regular NUMA node " << node_result;
        }
    } else {
        NIXL_WARN << "Could not determine NUMA node for memory at " << addr << " (errno=" << errno
                  << ")";
    }

    out = metadata;
    return NIXL_SUCCESS;
}

nixl_status_t
nixlCxlExpEngine::deregisterMem(nixlBackendMD *meta) {
    if (!meta) {
        return NIXL_ERR_INVALID_PARAM;
    }

    nixlCxlExpMetadata *md = static_cast<nixlCxlExpMetadata *>(meta);
    delete md;

    return NIXL_SUCCESS;
}

nixl_status_t
nixlCxlExpEngine::prepXfer(const nixl_xfer_op_t &operation,
                           const nixl_meta_dlist_t &local,
                           const nixl_meta_dlist_t &remote,
                           const std::string &remote_agent,
                           nixlBackendReqH *&handle,
                           const nixl_opt_b_args_t *opt_args) const {
    // We need to check initialized_ but we can't modify member variables in a const method
    if (!initialized_) {
        return NIXL_ERR_BACKEND;
    }

    // Validate operation type
    if (operation != NIXL_READ && operation != NIXL_WRITE) {
        NIXL_ERROR << "CXL backend only supports READ and WRITE operations";
        return NIXL_ERR_INVALID_PARAM;
    }

    // Check descriptor counts match
    if (local.descCount() != remote.descCount()) {
        NIXL_ERROR << "Local and remote descriptor counts must match";
        return NIXL_ERR_INVALID_PARAM;
    }

    // Create request handle
    auto req_handle = new nixlCxlExpBackendReqH();
    req_handle->local_descs = &local;
    req_handle->remote_descs = &remote;
    req_handle->op_type = operation;
    req_handle->operation_completed = false;

    handle = req_handle;
    return NIXL_SUCCESS;
}

nixl_status_t
nixlCxlExpEngine::postXfer(const nixl_xfer_op_t &operation,
                           const nixl_meta_dlist_t &local,
                           const nixl_meta_dlist_t &remote,
                           const std::string &remote_agent,
                           nixlBackendReqH *&handle,
                           const nixl_opt_b_args_t *opt_args) const {
    if (!initialized_) {
        return NIXL_ERR_BACKEND;
    }

    nixlCxlExpBackendReqH *req = static_cast<nixlCxlExpBackendReqH *>(handle);

    // Choose NUMA node of the source buffer (if CXL)
    int target_node = -1;
    const nixl_meta_dlist_t &src_list = (operation == NIXL_READ) ? remote : local;
    if (src_list.descCount() > 0) {
        auto *md = dynamic_cast<nixlCxlExpMetadata *>(src_list[0].metadataP);
        if (md) target_node = md->numa_node_id;
    }

    struct bitmask *orig_mask = nullptr;
    struct bitmask *tgt_mask = nullptr;
    if (target_node >= 0) {
        orig_mask = numa_get_run_node_mask();
        tgt_mask = numa_allocate_nodemask();
        numa_bitmask_clearall(tgt_mask);
        numa_bitmask_setbit(tgt_mask, target_node);
        if (numa_run_on_node_mask(tgt_mask) != 0)
            NIXL_WARN << "Failed to bind to NUMA node " << target_node;
    }

    // Perform the memory transfer for each descriptor pair
    for (int i = 0; i < local.descCount(); i++) {
        const nixlMetaDesc &local_desc = local[i];
        const nixlMetaDesc &remote_desc = remote[i];

        // Source and destination addresses
        void *src_addr, *dst_addr;

        if (operation == NIXL_READ) {
            src_addr = reinterpret_cast<void *>(remote_desc.addr);
            dst_addr = reinterpret_cast<void *>(local_desc.addr);
        } else { // NIXL_WRITE
            src_addr = reinterpret_cast<void *>(local_desc.addr);
            dst_addr = reinterpret_cast<void *>(remote_desc.addr);
        }

        // Perform the memory copy
        std::memcpy(dst_addr, src_addr, local_desc.len);
    }

    // Mark operation as completed
    req->operation_completed = true;

    // Restore original affinity
    if (tgt_mask) {
        numa_run_on_node_mask(orig_mask);
        numa_free_nodemask(tgt_mask);
        numa_free_nodemask(orig_mask);
    }

    return NIXL_SUCCESS;
}

nixl_status_t
nixlCxlExpEngine::checkXfer(nixlBackendReqH *handle) const {
    if (!handle) {
        return NIXL_ERR_INVALID_PARAM;
    }

    nixlCxlExpBackendReqH *req = static_cast<nixlCxlExpBackendReqH *>(handle);

    // Since our implementation is synchronous, the operation is always completed
    // after postXfer
    return req->operation_completed ? NIXL_SUCCESS : NIXL_IN_PROG;
}

nixl_status_t
nixlCxlExpEngine::releaseReqH(nixlBackendReqH *handle) const {
    if (!handle) {
        return NIXL_ERR_INVALID_PARAM;
    }

    nixlCxlExpBackendReqH *req = static_cast<nixlCxlExpBackendReqH *>(handle);
    delete req;

    return NIXL_SUCCESS;
}

// Update the estimateXferCost method signature to match the base class
nixl_status_t
nixlCxlExpEngine::estimateXferCost(const nixl_xfer_op_t &op,
                                   const nixl_meta_dlist_t &local,
                                   const nixl_meta_dlist_t &remote,
                                   const std::string &,
                                   nixlBackendReqH *const &,
                                   std::chrono::microseconds &duration,
                                   std::chrono::microseconds &err,
                                   nixl_cost_t &method,
                                   const nixl_opt_args_t *) const {
    if (!initialized_) return NIXL_ERR_BACKEND;

    // Locate a descriptor that lives on a CXL node
    const nixl_meta_dlist_t *src_lists[2] = {&local, &remote};
    const nixl_meta_dlist_t *cxl_list = nullptr;
    const nixlCxlExpMetadata *cxl_md = nullptr;

    for (const auto *lst : src_lists) {
        for (int i = 0; i < lst->descCount(); ++i) {
            auto *md = dynamic_cast<nixlCxlExpMetadata *>((*lst)[i].metadataP);
            if (md && cxl_nodes_.count(md->numa_node_id)) {
                cxl_list = lst;
                cxl_md = md;
                break;
            }
        }
        if (cxl_md) break;
    }

    if (!cxl_md) { // nothing on CXL
        duration = std::chrono::seconds(1);
        err = std::chrono::milliseconds(500);
        return NIXL_ERR_NOT_FOUND;
    }

    // Pull per-node performance numbers
    const auto it = cxl_node_info_.find(cxl_md->numa_node_id);
    if (it == cxl_node_info_.end()) { // node discovered but metrics absent
        duration = std::chrono::milliseconds(500);
        err = std::chrono::milliseconds(250);
        return NIXL_SUCCESS;
    }

    uint64_t bw =
        (op == NIXL_WRITE) ? it->second.write_bandwidth_mbps : it->second.read_bandwidth_mbps;
    uint32_t lat_ns = (op == NIXL_WRITE) ? it->second.write_latency_ns : it->second.read_latency_ns;

    if (bw == 0) bw = 30'000; // last-ditch default for both paths

    // 3. Aggregate size & compute
    size_t bytes = 0;
    for (int i = 0; i < cxl_list->descCount(); ++i)
        bytes += (*cxl_list)[i].len;

    const double bw_Bps = bw * 1024.0 * 1024.0;
    const double xfer_us = (static_cast<double>(bytes) / bw_Bps) * 1'000'000.0;
    const double total_us = xfer_us + (lat_ns / 1'000.0);

    duration = std::chrono::microseconds(static_cast<int64_t>(total_us));
    err = std::chrono::microseconds(duration.count() / 10);
    method = nixl_cost_t::ANALYTICAL_BACKEND;

    NIXL_DEBUG << "CXL cost: " << bytes << " B via node " << cxl_md->numa_node_id << " -> "
               << duration.count() << " µs @ " << bw << " MB/s";

    return NIXL_SUCCESS;
}