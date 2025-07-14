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
    nixl_mem_list_t mems;
    mems.push_back(DRAM_SEG); // Regular memory
    // Add custom memory type for CXL if needed in the future
    return mems;
}

bool
nixlCxlExpEngine::checkSNC() {
    // Check for Sub-NUMA Clustering if relevant for your system
    // Placeholder implementation
    return false;
}

bool
nixlCxlExpEngine::discoverCXLNodes() {
    // Get total number of NUMA nodes
    int max_node = numa_max_node();
    if (max_node < 0) {
        NIXL_ERROR << "Failed to get maximum NUMA node";
        return false;
    }

    NIXL_INFO << "Discover CXL Nodes: max_node=" << max_node;

    // First try direct CXL sysfs path discovery (more reliable on newer kernels)
    const std::string cxl_path = "/sys/bus/cxl/devices";
    NIXL_INFO << "Checking for CXL devices at path: " << cxl_path;
    
    DIR *dir = opendir(cxl_path.c_str());
    if (!dir) {
        NIXL_INFO << "CXL path not found or cannot be opened: " << cxl_path << " (errno=" << errno << " " << strerror(errno) << ")";
    } else {
        NIXL_INFO << "Successfully opened CXL path: " << cxl_path;
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string name = entry->d_name;
            NIXL_DEBUG << "Found directory entry: " << name;
            
            // Look for memory devices (mem*) or regions
            if (name != "." && name != ".." &&
                ((name.find("mem") == 0) || (name.find("region") == 0))) {
                NIXL_INFO << "Found potential CXL device/region: " << name;

                std::string numa_node_path = cxl_path + "/" + name + "/numa_node";
                NIXL_DEBUG << "Checking path: " << numa_node_path;
                
                if (!fileExists(numa_node_path)) {
                    NIXL_DEBUG << "Path not found: " << numa_node_path;
                    // For CXL regions, check in access0 directory
                    numa_node_path = cxl_path + "/" + name + "/access0/numa_node";
                    NIXL_DEBUG << "Checking alternative path: " << numa_node_path;
                    
                    if (!fileExists(numa_node_path)) {
                        NIXL_DEBUG << "Path not found: " << numa_node_path;
                        // Try alternative paths for different kernel versions
                        numa_node_path = cxl_path + "/" + name + "/target_node";
                        NIXL_DEBUG << "Checking last alternative path: " << numa_node_path;
                    }
                }

                if (fileExists(numa_node_path)) {
                    NIXL_INFO << "Found NUMA node path: " << numa_node_path;
                    int node_id = readUint64FromFile(numa_node_path);
                    NIXL_INFO << "Read NUMA node ID: " << node_id;
                    
                    if (node_id >= 0 && node_id <= max_node) {
                        NIXL_INFO << "Valid NUMA node ID for CXL device: " << node_id;
                        
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
                            NIXL_INFO << "Direct metrics reading failed, trying performance metric reader...";
                            readCXLPerformanceMetrics(node_id, node_info);
                        }

                        NIXL_INFO << "Discovered CXL device " << name << " on NUMA node " << node_id;
                        NIXL_INFO << "  Read BW: " << node_info.read_bandwidth_mbps
                                  << " MB/s, Write BW: " << node_info.write_bandwidth_mbps
                                  << " MB/s";
                        NIXL_INFO << "  Read latency: " << node_info.read_latency_ns
                                  << " ns, Write latency: " << node_info.write_latency_ns << " ns";

                        cxl_node_info_[node_id] = node_info;
                        cxl_nodes_[node_id] = node_info.read_bandwidth_mbps;
                        NIXL_INFO << "Added node " << node_id << " to cxl_nodes_ and cxl_node_info_ maps";
                    } else {
                        NIXL_WARN << "Invalid NUMA node ID: " << node_id << " (max_node=" << max_node << ")";
                    }
                } else {
                    NIXL_INFO << "Could not find any valid NUMA node path for: " << name;
                }
            }
        }
        closedir(dir);
        NIXL_INFO << "Finished reading CXL device directory";
    }

    // If direct method found CXL nodes, we're done
    if (!cxl_nodes_.empty()) {
        NIXL_INFO << "CXL nodes found via direct sysfs path: " << cxl_nodes_.size() << " nodes";
        return true;
    }

    // Fall back to heuristic-based approach
    NIXL_WARN << "No CXL devices found via direct sysfs, falling back to heuristics";

    // Detect CXL nodes by examining node distance and characteristics
    for (int i = 0; i <= max_node; i++) {
        // Skip nodes that aren't configured or available
        if (!numa_bitmask_isbitset(numa_all_nodes_ptr, i)) {
            continue;
        }

        // Check if this is a CXL node based on distance or other properties
        bool is_cxl_node = false;

        // 1. Check distance from node 0 (CPU node)
        if (numa_distance(0, i) > 20) { // Threshold may vary
            is_cxl_node = true;
        }

        // 2. Check memory size and look for CXL-specific indicators
        long long node_free_size = numa_node_size64(i, nullptr);
        if (node_free_size > 0) {
            std::string node_path = "/sys/devices/system/node/node" + std::to_string(i);
            if (fileExists(node_path + "/memory_side_cache") ||
                fileExists(node_path + "/cxl_device")) {
                is_cxl_node = true;
                NIXL_INFO << "Found CXL-specific indicators for node " << i;
            }
        }

        if (is_cxl_node) {
            // Create node info structure with real values when possible
            CXLNodeInfo node_info{};
            readCXLPerformanceMetrics(i, node_info);

            NIXL_INFO << "CXL Node " << i << " metrics - Read BW: " << node_info.read_bandwidth_mbps
                      << " MB/s, Write BW: " << node_info.write_bandwidth_mbps << " MB/s";
            NIXL_INFO << "  Read latency: " << node_info.read_latency_ns
                      << " ns, Write latency: " << node_info.write_latency_ns << " ns";

            cxl_node_info_[i] = node_info;
            cxl_nodes_[i] = node_info.read_bandwidth_mbps;
        }
    }

    return !cxl_nodes_.empty();
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

    if (nixl_mem != DRAM_SEG) {
        NIXL_ERROR << "CXL backend only supports DRAM_SEG memory type";
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
        NIXL_WARN << "Could not determine NUMA node for memory at " << addr;
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
nixlCxlExpEngine::estimateXferCost(const nixl_xfer_op_t &operation,
                                   const nixl_meta_dlist_t &local,
                                   const nixl_meta_dlist_t &remote,
                                   const std::string &remote_agent,
                                   nixlBackendReqH *const &handle,
                                   std::chrono::microseconds &duration,
                                   std::chrono::microseconds &err_margin,
                                   nixl_cost_t &method,
                                   const nixl_opt_args_t *opt_args) const {
    if (!initialized_) {
        return NIXL_ERR_BACKEND;
    }

    // Determine which side is using CXL memory
    const nixl_meta_dlist_t *cxl_list = nullptr;
    nixlCxlExpMetadata *cxl_md = nullptr;

    // First, check if local list has CXL memory
    for (int i = 0; i < local.descCount(); i++) {
        auto md = dynamic_cast<nixlCxlExpMetadata *>(local[i].metadataP);
        if (md && cxl_nodes_.find(md->numa_node_id) != cxl_nodes_.end()) {
            cxl_list = &local;
            cxl_md = md;
            break;
        }
    }

    // If local list doesn't use CXL, check remote list
    if (!cxl_md) {
        for (int i = 0; i < remote.descCount(); i++) {
            auto md = dynamic_cast<nixlCxlExpMetadata *>(remote[i].metadataP);
            if (md && cxl_nodes_.find(md->numa_node_id) != cxl_nodes_.end()) {
                cxl_list = &remote;
                cxl_md = md;
                break;
            }
        }
    }

    // If no CXL memory is involved, this plugin shouldn't be used
    if (!cxl_md || !cxl_list) {
        NIXL_WARN << "CXL cost estimation called, but no CXL memory found";
        duration = std::chrono::microseconds(1000000); // High cost: 1 second
        err_margin = std::chrono::microseconds(500000); // 0.5 second error margin
        return NIXL_ERR_NOT_FOUND;
    }

    // Get CXL node information
    int numa_node = cxl_md->numa_node_id;
    auto it = cxl_node_info_.find(numa_node);
    if (it == cxl_node_info_.end()) {
        // Fall back to the regular map if node_info isn't available
        duration = std::chrono::microseconds(500000); // Medium cost: 0.5 second
        err_margin = std::chrono::microseconds(250000); // 0.25 second error margin
        return NIXL_SUCCESS;
    }

    const CXLNodeInfo &node_info = it->second;

    // Get the appropriate bandwidth and latency based on operation
    uint64_t bandwidth_mbps =
        (operation == NIXL_WRITE) ? node_info.write_bandwidth_mbps : node_info.read_bandwidth_mbps;
    uint32_t latency_ns =
        (operation == NIXL_WRITE) ? node_info.write_latency_ns : node_info.read_latency_ns;

    /* Avoid divide‑by‑zero and identify the cost model */
    if (bandwidth_mbps == 0) {
        bandwidth_mbps = 30000; // fallback 30 GB/s
    }
    // method = NIXL_COST_MODEL_ANALYTIC;  // mark that we used the analytic model

    // Calculate total transfer size in bytes
    size_t total_size = 0;
    for (int i = 0; i < cxl_list->descCount(); i++) {
        total_size += (*cxl_list)[i].len;
    }

    // Calculate transfer time
    double latency_us = static_cast<double>(latency_ns) / 1000.0;
    double bandwidth_bytes_per_sec = static_cast<double>(bandwidth_mbps) * 1024.0 * 1024.0;
    double transfer_time_us =
        (static_cast<double>(total_size) / bandwidth_bytes_per_sec) * 1000000.0;

    // Set the duration (latency + transfer time)
    duration = std::chrono::microseconds(static_cast<int64_t>(latency_us + transfer_time_us));

    // Set error margin (10% of duration)
    err_margin = std::chrono::microseconds(static_cast<int64_t>(duration.count() * 0.1));

    NIXL_DEBUG << "CXL cost estimation: size=" << total_size << "B, duration=" << duration.count()
               << "us, bandwidth=" << bandwidth_mbps << "MB/s";

    return NIXL_SUCCESS;
}