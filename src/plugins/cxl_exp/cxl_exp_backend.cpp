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

/**
 * Return the default key‑value options accepted by the experimental CXL
 * backend.
 *
 * @return A map whose keys are option names and whose values are defaults.
 */
nixl_b_params_t
get_cxl_exp_backend_options() {
    nixl_b_params_t params;
    params["numa_policy"] = "bind"; // Options: bind, preferred, interleave
    params["force_cxl_device"] = ""; // Empty means auto-detect
    return params;
}

/**
 * Read an unsigned 64‑bit value from a sysfs attribute.
 *
 * @param path Absolute path to the attribute.
 * @param[out] out Populated with the parsed value on success.
 * @return `true` if the attribute exists and was parsed, `false` otherwise.
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

    NIXL_INFO << "Initializing CXL Experimental Backend for agent: " << agent_name_;

    // First check if CXL devices exist in the system
    // This should be done before NUMA checks for faster failure
    if (!checkCXLDevicesExist()) {
        NIXL_ERROR << "No CXL devices found in system";
        this->initErr = true;
        return;
    }

    // Check if NUMA library is available
    if (numa_available() < 0) {
        NIXL_ERROR << "NUMA library not available";
        this->initErr = true;
        return;
    }

    // Check for Sub-NUMA Clustering (SNC) which might affect performance
    if (checkSNC()) {
        NIXL_WARN
            << "System has Sub-NUMA Clustering (SNC) enabled, which may affect CXL performance";
    }

    // Initialize NUMA topology and discover CXL nodes
    if (!discoverCXLNodes()) {
        NIXL_ERROR << "Failed to discover CXL NUMA nodes";
        this->initErr = true;
        return;
    }

    if (cxl_nodes_.empty()) {
        NIXL_ERROR << "No CXL NUMA nodes found in system";
        this->initErr = true;
        return;
    }

    NIXL_INFO << "Found " << cxl_nodes_.size() << " CXL NUMA nodes";
    for (const auto &[node_id, bandwidth] : cxl_nodes_) {
        NIXL_INFO << "  Node " << node_id << " with bandwidth " << bandwidth << " MB/s";
    }

    initialized_ = true;
}

/**
 * Test whether at least one CXL memory device is exposed under
 * `/sys/bus/cxl/devices`.
 *
 * @return `true` if a device entry of type *mem* or *region* is found,
 *         `false` otherwise.
 */
bool
nixlCxlExpEngine::checkCXLDevicesExist() {
    // Check if CXL sysfs path exists
    const std::string cxl_path = "/sys/bus/cxl/devices";
    DIR *dir = opendir(cxl_path.c_str());

    if (!dir) {
        NIXL_WARN << "CXL sysfs path \"" << cxl_path << "\" not found";
        NIXL_WARN << "Ensure the kernel CXL driver is loaded (errno=" << errno << " - "
                  << strerror(errno) << ")";
        return false;
    }

    // Check if there are any CXL devices
    struct dirent *entry;
    bool found_device = false;

    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        // Skip "." and ".." entries
        if (name != "." && name != "..") {
            // Check if this is a CXL memory device
            if (name.find("mem") == 0 || name.find("region") == 0) {
                found_device = true;
                break;
            }
        }
    }

    closedir(dir);

    if (!found_device) {
        NIXL_WARN << "No CXL memory devices found in " << cxl_path;
    } else {
        NIXL_DEBUG << "CXL memory devices found in " << cxl_path;
    }

    return found_device;
}

/**
 * Detect whether Sub‑NUMA Clustering (SNC) is enabled.
 *
 * The method looks for kernel hints in sysfs, `/proc/cpuinfo`, and NUMA
 * distance tables.
 *
 * @return `true` if SNC is likely enabled, `false` otherwise.
 */
bool
nixlCxlExpEngine::checkSNC() {
    // Check common locations for SNC status
    const std::vector<std::string> snc_paths = {
        "/sys/devices/system/node/snc_enabled",
        "/proc/cpuinfo", // Will check content for SNC indicators
        "/sys/firmware/acpi/tables/SLIT" // Presence can indicate SNC
    };

    // Check if any of the SNC indicator files exist
    for (const auto &path : snc_paths) {
        if (path == "/proc/cpuinfo") {
            // Special case: check /proc/cpuinfo content for SNC indicators
            std::ifstream cpuinfo(path);
            if (cpuinfo.good()) {
                std::string line;
                while (std::getline(cpuinfo, line)) {
                    // Look for SNC indicators in CPU flags or other entries
                    if (line.find("snc") != std::string::npos ||
                        line.find("SNC") != std::string::npos) {
                        NIXL_DEBUG << "SNC indicator found in " << path << ": " << line;
                        return true;
                    }
                }
            }
        } else if (fileExists(path)) {
            // For simple files, just check existence or content
            std::ifstream snc_file(path);
            if (snc_file.good()) {
                std::string content;
                snc_file >> content;
                // If the file contains a value of 1 or "enabled", SNC is enabled
                if (content == "1" || content == "enabled") {
                    NIXL_DEBUG << "SNC enabled according to " << path;
                    return true;
                }
            }
        }
    }

    // Check NUMA node distances for SNC pattern
    // SNC typically creates clusters with much lower distance within clusters
    if (numa_available() >= 0) {
        int max_node = numa_max_node();
        if (max_node > 1) { // Need at least 2 nodes for SNC
            // Look for non-uniform distance pattern indicating SNC
            for (int i = 0; i <= max_node; i++) {
                for (int j = i + 1; j <= max_node; j++) {
                    int dist_ij = numa_distance(i, j);
                    // If we find unusual distance patterns, it may indicate SNC
                    if (dist_ij > 20 && dist_ij < 30) {
                        NIXL_DEBUG << "Possible SNC detected from NUMA distances: "
                                   << "Distance between node " << i << " and " << j << " is "
                                   << dist_ij;
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

/**
 * Enumerate NUMA nodes backed by CXL memory and gather performance metrics.
 *
 * This routine fills both `cxl_nodes_` and `cxl_node_info_`.
 *
 * @return `true` if at least one suitable NUMA node is discovered,
 *         `false` otherwise.
 */
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

    // Track if we're using a new or old kernel based on what sysfs files we find
    bool using_modern_kernel = false;
    bool found_any_device = false;

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        NIXL_DEBUG << "Found directory entry: " << name;

        // Look for memory devices (mem*) or regions
        if (name != "." && name != ".." &&
            ((name.find("mem") == 0) || (name.find("region") == 0))) {

            found_any_device = true;
            NIXL_INFO << "Found potential CXL device/region: " << name;

            // ---------- Resolve NUMA node for this CXL endpoint ----------
            // Try multiple paths based on different kernel versions
            const std::vector<std::string> cand = {
                cxl_path + "/" + name + "/numa_node",
                cxl_path + "/" + name + "/access0/numa_node",
                cxl_path + "/" + name + "/target_node",
            };

            uint64_t node_val = 0;
            bool have_id = false;
            std::string found_path;

            for (const auto &p : cand) {
                if (readSysfsU64(p, node_val)) {
                    have_id = true;
                    found_path = p;
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

            NIXL_INFO << "Found NUMA node " << node_id << " for CXL device " << name
                      << " via path: " << found_path;

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
            // These files only exist in newer kernels (6.1+)
            std::string read_bw_path = access_path + "/read_bandwidth";
            std::string write_bw_path = access_path + "/write_bandwidth";
            std::string read_lat_path = access_path + "/read_latency";
            std::string write_lat_path = access_path + "/write_latency";

            uint64_t read_bw = 0, write_bw = 0;
            uint64_t read_lat = 0, write_lat = 0;

            // Check for modern kernel sysfs files
            if (fileExists(read_bw_path) || fileExists(write_bw_path) ||
                fileExists(read_lat_path) || fileExists(write_lat_path)) {
                using_modern_kernel = true;

                NIXL_INFO << "Modern CXL sysfs interface detected - reading performance metrics";

                read_bw = readUint64FromFile(read_bw_path);
                write_bw = readUint64FromFile(write_bw_path);
                read_lat = readUint64FromFile(read_lat_path);
                write_lat = readUint64FromFile(write_lat_path);

                NIXL_INFO << "Metrics from sysfs - Read BW: " << read_bw
                          << ", Write BW: " << write_bw << ", Read latency: " << read_lat
                          << ", Write latency: " << write_lat;
            }

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

    if (!found_any_device) {
        NIXL_WARN << "No CXL devices found in " << cxl_path;
        return false;
    }

    if (!using_modern_kernel) {
        NIXL_WARN << "Using older kernel without CXL performance metrics in sysfs";
        NIXL_WARN << "Performance estimates will be based on default values";
    }

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

/**
 * Check whether a file or directory exists.
 *
 * @param path Absolute path to test.
 * @return `true` if the path can be opened, `false` otherwise.
 */
bool
nixlCxlExpEngine::fileExists(const std::string &path) {
    std::ifstream file(path);
    return file.good();
}

/**
 * Read an unsigned 64‑bit integer from a text file.
 *
 * @param path Absolute path of the file.
 * @return Parsed value, or 0 if the file does not exist or cannot be read.
 */
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

/**
 * Populate bandwidth and latency figures for a given NUMA node.
 *
 * @param node_id Kernel NUMA node identifier.
 * @param node_info Structure to update in place.
 */
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

/**
 * Associate a memory range with the backend and record NUMA information.
 *
 * @param mem       Descriptor of the memory blob supplied by the caller.
 * @param nixl_mem  Segment tag (e.g. DRAM_SEG or CXL_EXP_SEG).
 * @param[out] out  Newly allocated backend metadata structure.
 * @return `NIXL_SUCCESS` on success; an error code otherwise.
 */
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

/**
 * Release backend metadata produced by `registerMem`.
 *
 * @param meta Pointer returned earlier by `registerMem`.
 * @return `NIXL_SUCCESS` on success; an error code otherwise.
 */
nixl_status_t
nixlCxlExpEngine::deregisterMem(nixlBackendMD *meta) {
    if (!meta) {
        return NIXL_ERR_INVALID_PARAM;
    }

    nixlCxlExpMetadata *md = static_cast<nixlCxlExpMetadata *>(meta);
    delete md;

    return NIXL_SUCCESS;
}

/**
 * Validate a transfer request and create an internal handle.
 *
 * @param operation  Transfer direction (`NIXL_READ` or `NIXL_WRITE`).
 * @param local      Local descriptor list.
 * @param remote     Remote descriptor list.
 * @param remote_agent Identifier of the peer agent (unused for local backend).
 * @param[out] handle Newly allocated request handle.
 * @param opt_args   Optional backend‑specific arguments.
 * @return `NIXL_SUCCESS` on success; an error code otherwise.
 */
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

/**
 * Execute a synchronous memory transfer described by a handle.
 *
 * @param operation See `prepXfer`.
 * @param local     Local descriptor list.
 * @param remote    Remote descriptor list.
 * @param remote_agent Identifier of the peer agent (unused).
 * @param handle    Handle created by `prepXfer`.
 * @param opt_args  Optional backend‑specific arguments.
 * @return `NIXL_SUCCESS` on success; an error code otherwise.
 */
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
    // This optimization ensures we bind to the correct NUMA node during the transfer
    int target_node = -1;

    // Determine source descriptor list based on operation type
    const nixl_meta_dlist_t &src_list = (operation == NIXL_READ) ? remote : local;

    // Find CXL metadata in first descriptor to determine NUMA node
    if (src_list.descCount() > 0) {
        auto *md = dynamic_cast<nixlCxlExpMetadata *>(src_list[0].metadataP);
        if (md) {
            target_node = md->numa_node_id;
            NIXL_DEBUG << "Using NUMA node " << target_node << " for transfer";
        }
    }

    // Save and modify CPU affinity for optimal transfer
    struct bitmask *orig_mask = nullptr;
    struct bitmask *tgt_mask = nullptr;

    // If we found a valid NUMA node, bind to it for the duration of the transfer
    if (target_node >= 0) {
        NIXL_DEBUG << "Temporarily binding transfer to NUMA node " << target_node;

        // Save current CPU affinity to restore later
        orig_mask = numa_get_run_node_mask();

        // Create mask for target node
        tgt_mask = numa_allocate_nodemask();
        numa_bitmask_clearall(tgt_mask);
        numa_bitmask_setbit(tgt_mask, target_node);

        // Apply the mask to bind to the target node
        if (numa_run_on_node_mask(tgt_mask) != 0) {
            NIXL_WARN << "Failed to bind to NUMA node " << target_node;
        }
    }

    // Perform the memory transfer for each descriptor pair
    for (int i = 0; i < local.descCount(); i++) {
        const nixlMetaDesc &local_desc = local[i];
        const nixlMetaDesc &remote_desc = remote[i];

        // Determine source and destination addresses based on operation type
        void *src_addr, *dst_addr;

        if (operation == NIXL_READ) {
            // In READ operation, data flows from remote to local
            src_addr = reinterpret_cast<void *>(remote_desc.addr);
            dst_addr = reinterpret_cast<void *>(local_desc.addr);
            NIXL_DEBUG << "READ: " << src_addr << " -> " << dst_addr << " (" << local_desc.len
                       << " bytes)";
        } else { // NIXL_WRITE
            // In WRITE operation, data flows from local to remote
            src_addr = reinterpret_cast<void *>(local_desc.addr);
            dst_addr = reinterpret_cast<void *>(remote_desc.addr);
            NIXL_DEBUG << "WRITE: " << src_addr << " -> " << dst_addr << " (" << local_desc.len
                       << " bytes)";
        }

        // Perform the memory copy
        // This is a simple memcpy implementation - future versions could use optimized methods
        // based on the CXL hardware capabilities
        std::memcpy(dst_addr, src_addr, local_desc.len);
    }

    // Mark operation as completed
    req->operation_completed = true;

    // Restore original CPU affinity if we modified it
    if (tgt_mask) {
        NIXL_DEBUG << "Restoring original CPU affinity";
        numa_run_on_node_mask(orig_mask);
        numa_free_nodemask(tgt_mask);
        numa_free_nodemask(orig_mask);
    }

    return NIXL_SUCCESS;
}

/**
 * Query completion status of a transfer.
 *
 * @param handle Request handle created by `prepXfer`.
 * @return `NIXL_SUCCESS` if completed, `NIXL_IN_PROG` otherwise.
 */
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

/**
 * Destroy a request handle allocated by `prepXfer`.
 *
 * @param handle Pointer to the handle.
 * @return `NIXL_SUCCESS` on success; an error code otherwise.
 */
nixl_status_t
nixlCxlExpEngine::releaseReqH(nixlBackendReqH *handle) const {
    if (!handle) {
        return NIXL_ERR_INVALID_PARAM;
    }

    nixlCxlExpBackendReqH *req = static_cast<nixlCxlExpBackendReqH *>(handle);
    delete req;

    return NIXL_SUCCESS;
}

/**
 * Provide a best‑effort duration estimate for a transfer.
 *
 * @param op       Transfer direction.
 * @param local    Local descriptor list.
 * @param remote   Remote descriptor list.
 * @param duration Output parameter set to the estimated time.
 * @param err      Output parameter for the error margin.
 * @param method   Output parameter identifying the cost‑model used.
 * @return `NIXL_SUCCESS` on success; an error code otherwise.
 */
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

    // Search through all descriptors to find one that uses CXL memory
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

    // If no CXL memory is involved, return an error
    if (!cxl_md) { // nothing on CXL
        // Use a more conservative estimate for non-CXL memory - 250ms instead of 1s
        duration = std::chrono::milliseconds(250);
        err = std::chrono::milliseconds(100);
        return NIXL_ERR_NOT_FOUND;
    }

    // Pull per-node performance numbers from our database
    const auto it = cxl_node_info_.find(cxl_md->numa_node_id);
    if (it == cxl_node_info_.end()) {
        // Node discovered but metrics absent - use moderate defaults
        // 200ms is more reasonable than 500ms for most CXL devices
        duration = std::chrono::milliseconds(200);
        err = std::chrono::milliseconds(50);
        return NIXL_SUCCESS;
    }

    // Get bandwidth and latency based on operation type
    uint64_t bw =
        (op == NIXL_WRITE) ? it->second.write_bandwidth_mbps : it->second.read_bandwidth_mbps;

    uint32_t lat_ns = (op == NIXL_WRITE) ? it->second.write_latency_ns : it->second.read_latency_ns;

    // Calculate transfer time using bandwidth and latency
    size_t bytes = 0;
    for (int i = 0; i < cxl_list->descCount(); ++i) {
        bytes += (*cxl_list)[i].len;
    }

    if (bw == 0) bw = 30'000; // 30 GB/s default
    // Default fallback if bandwidth somehow wasn't set

    double total_us = 0;
    if (lat_ns > 0) {
        total_us += lat_ns / 1'000.0; // Convert ns to μs
    }
    if (bw > 0) {
        double bw_Bps = bw * 1024.0 * 1024.0; // Convert MB/s to B/s
        double xfer_us = (static_cast<double>(bytes) / bw_Bps) * 1'000'000.0; // Transfer time in μs
        total_us += xfer_us;
    }

    NIXL_DEBUG << "CXL cost estimate: " << bytes << " bytes via node " << cxl_md->numa_node_id
               << " -> " << duration.count() << " µs @ " << bw << " MB/s, "
               << "latency: " << lat_ns << " ns";

    method = nixl_cost_t::ANALYTICAL_BACKEND; // We're using an analytical model
    err = std::chrono::microseconds(duration.count() / 10); // 10% error margin
    duration = std::chrono::microseconds(static_cast<int64_t>(total_us));

    // Set output parameters
    return NIXL_SUCCESS;
}

/**
 * Determine whether CXL memory is mapped as *system‑ram* or *devdax*.
 *
 * @return `true` if the preferred *system‑ram* mode is active, `false`
 *         otherwise.
 */
bool
nixlCxlExpEngine::checkCXLSystemRamMode() {
    // Check if we have CXL devices that appear as regular system RAM
    bool system_ram_mode = false;

    // Look for CXL memory that appears in system memory map
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.good()) {
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.find("MemTotal") != std::string::npos) {
                // System reports memory, but we need to check if some is from CXL
                NIXL_DEBUG << "Found memory info: " << line;
                break;
            }
        }
    }

    // Check if CXL devices are mapped to NUMA nodes
    if (numa_available() >= 0) {
        int max_node = numa_max_node();
        if (max_node >= 0) {
            for (int i = 0; i <= max_node; i++) {
                if (!numa_bitmask_isbitset(numa_all_nodes_ptr, i)) {
                    continue;
                }

                // Check if this node is associated with CXL
                std::string node_path = "/sys/devices/system/node/node" + std::to_string(i);
                std::string cxl_indicator = node_path + "/device/cxl";

                if (fileExists(cxl_indicator) || fileExists(node_path + "/device/devtype") ||
                    fileExists(node_path + "/memory_side_cache")) {
                    NIXL_INFO << "NUMA node " << i
                              << " appears to be CXL memory in system-ram mode";
                    system_ram_mode = true;
                }
            }
        }
    }

    // Check for device DAX mode
    bool devdax_mode = false;
    DIR *dir = opendir("/dev/dax");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string name = entry->d_name;
            if (name != "." && name != ".." && name.find("dax") == 0) {
                // Look for association with CXL
                std::string dax_path = "/sys/bus/dax/devices/" + name;
                if (fileExists(dax_path + "/cxl") || fileExists(dax_path + "/devtype")) {
                    NIXL_INFO << "Found CXL memory in device DAX mode: " << name;
                    devdax_mode = true;
                }
            }
        }
        closedir(dir);
    }

    // Log the detected mode
    if (system_ram_mode && devdax_mode) {
        NIXL_INFO << "CXL memory found in both system-ram and device DAX modes";
    } else if (system_ram_mode) {
        NIXL_INFO << "CXL memory is in system-ram mode (preferred)";
    } else if (devdax_mode) {
        NIXL_WARN
            << "CXL memory is in device DAX mode - this plugin works best with system-ram mode";
    } else {
        NIXL_WARN << "Could not determine CXL memory mode";
    }

    return system_ram_mode;
}

/** Destructor: logs shutdown and performs clean‑up. */
nixlCxlExpEngine::~nixlCxlExpEngine() {
    // No special cleanup needed for now
    NIXL_INFO << "Destroying CXL Experimental Backend for agent: " << agent_name_;
    // Any cleanup code would go here
}

/**
 * Return the list of memory segment types supported by this backend.
 *
 * @return A list containing `DRAM_SEG` and `CXL_EXP_SEG`.
 */
nixl_mem_list_t
nixlCxlExpEngine::getSupportedMems() const {
    nixl_mem_list_t mems;
    mems.push_back(DRAM_SEG);
    mems.push_back(CXL_EXP_SEG);
    return mems;
}