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

    // Detect CXL nodes by examining node distance and characteristics
    // This is a simplified placeholder implementation
    for (int i = 0; i <= max_node; i++) {
        // Skip nodes that aren't configured or available
        if (!numa_bitmask_isbitset(numa_nodes_ptr, i)) {
            continue;
        }

        // Check if this is a CXL node based on distance or other properties
        // This is highly system-specific and may need adaptation
        bool is_cxl_node = false;

        // Example criteria (may need adjustment for your system):
        // 1. Check distance from node 0 (CPU node)
        if (numa_distance(0, i) > 20) { // Threshold may vary
            is_cxl_node = true;
        }

        // 2. Check memory size (CXL might have different characteristics)
        long long node_free_size = numa_node_size64(i, nullptr);
        if (node_free_size > 0) {
            // Additional checks if needed
        }

        if (is_cxl_node) {
            // Store node with a bandwidth estimate
            // This is a placeholder; actual bandwidth would depend on hardware
            uint64_t estimated_bandwidth = 16000; // MB/s
            cxl_nodes_[i] = estimated_bandwidth;
        }
    }

    return true;
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