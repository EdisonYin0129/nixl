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

#ifndef __CXL_EXP_BACKEND_H
#define __CXL_EXP_BACKEND_H

#include <nixl.h>
#include <nixl_types.h>
#include <backend/backend_engine.h>
#include "common/nixl_log.h"
#include <numa.h>
#include <vector>
#include <map>
#include <string>
#include <memory>

// Forward declarations
class nixlCxlExpMetadata;
class nixlCxlExpBackendReqH;

class nixlCxlExpMetadata : public nixlBackendMD {
public:
    nixlCxlExpMetadata() : nixlBackendMD(true), numa_node_id(-1) {}
    ~nixlCxlExpMetadata() = default;

    int numa_node_id;
    // Potentially cache bandwidth/latency info here in the future
};

class nixlCxlExpBackendReqH : public nixlBackendReqH {
public:
    nixlCxlExpBackendReqH() = default;
    ~nixlCxlExpBackendReqH() = default;

    // Pointers to the source and destination descriptor lists
    const nixl_meta_dlist_t *local_descs = nullptr;
    const nixl_meta_dlist_t *remote_descs = nullptr;
    nixl_xfer_op_t op_type = NIXL_READ;
    bool operation_completed = false;
};

class nixlCxlExpEngine : public nixlBackendEngine {
public:
    nixlCxlExpEngine(const nixlBackendInitParams *init_params);
    ~nixlCxlExpEngine();

    // Capability indicators
    bool
    supportsNotif() const override {
        return false;
    }
    bool
    supportsRemote() const override {
        return false;
    }
    bool
    supportsLocal() const override {
        return true;
    }
    bool
    supportsProgTh() const override {
        return false;
    }

    nixl_mem_list_t
    getSupportedMems() const override;

    // Connection management (simplified for local-only)
    nixl_status_t
    connect(const std::string &remote_agent) override {
        return NIXL_SUCCESS;
    }
    nixl_status_t
    disconnect(const std::string &remote_agent) override {
        return NIXL_SUCCESS;
    }

    // Memory Management
    nixl_status_t
    registerMem(const nixlBlobDesc &mem, const nixl_mem_t &nixl_mem, nixlBackendMD *&out) override;
    nixl_status_t
    deregisterMem(nixlBackendMD *meta) override;

    // Metadata Management
    nixl_status_t
    loadLocalMD(nixlBackendMD *input, nixlBackendMD *&output) override {
        output = input;
        return NIXL_SUCCESS;
    }
    nixl_status_t
    unloadMD(nixlBackendMD *input) override {
        return NIXL_SUCCESS;
    }

    // Transfer Operations
    nixl_status_t
    prepXfer(const nixl_xfer_op_t &operation,
             const nixl_meta_dlist_t &local,
             const nixl_meta_dlist_t &remote,
             const std::string &remote_agent,
             nixlBackendReqH *&handle,
             const nixl_opt_b_args_t *opt_args = nullptr) const override;

    nixl_status_t
    postXfer(const nixl_xfer_op_t &operation,
             const nixl_meta_dlist_t &local,
             const nixl_meta_dlist_t &remote,
             const std::string &remote_agent,
             nixlBackendReqH *&handle,
             const nixl_opt_b_args_t *opt_args = nullptr) const override;

    nixl_status_t
    checkXfer(nixlBackendReqH *handle) const override;

    nixl_status_t
    releaseReqH(nixlBackendReqH *handle) const override;

private:
    // Helper methods for initialization
    bool
    checkSNC();
    bool
    discoverCXLNodes();

    // Member variables
    std::string agent_name_;
    bool initialized_ = false;

    // Map of NUMA node ID to its properties (e.g., max bandwidth)
    std::map<int, uint64_t> cxl_nodes_;
};

nixl_b_params_t
get_cxl_exp_backend_options();

#endif // __CXL_EXP_BACKEND_H