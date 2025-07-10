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
#include <iostream>
#include <sstream>
#include <string>
#include <cassert>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <getopt.h>
#include <numa.h>
#include <memory>
#include <vector>
#include <gtest/gtest.h>

#include "cxl_exp_backend.h"
#include "common/nixl_log.h"
#include <backend/backend_engine.h>

using namespace std;

// Default test configuration
namespace {
constexpr int default_num_transfers = 10;
constexpr size_t default_transfer_size = 1 * 1024 * 1024; // 1MB
constexpr int line_width = 60;
const std::string line_str(line_width, '=');
constexpr size_t mb_size = 1024 * 1024;
constexpr size_t gb_size = 1024 * 1024 * 1024;
constexpr double
us_to_s(double us) {
    return us / 1000000.0;
}
constexpr int progress_bar_width = line_width - 2; // -2 for the brackets

// Custom deleter for aligned_alloc allocated memory
struct AlignedDeleter {
    void
    operator()(void *ptr) const {
        if (ptr) free(ptr);
    }
};

// Center text in a fixed-width string
std::string
center_str(const std::string &str) {
    return std::string((line_width - str.length()) / 2, ' ') + str;
}

// Print a phase title
std::string
phase_title(const std::string &title) {
    static int phase_num = 1;
    return "PHASE " + std::to_string(phase_num++) + ": " + title;
}

// Print a section title
void
print_segment_title(const std::string &title) {
    std::cout << std::endl << line_str << std::endl;
    std::cout << center_str(title) << std::endl;
    std::cout << line_str << std::endl;
}

// Format duration for display
std::string
format_duration(nixlTime::us_t us) {
    nixlTime::ms_t ms = us / 1000.0;
    if (ms < 1000) {
        return std::to_string((int)ms) + " ms";
    }
    double seconds = ms / 1000.0;
    std::stringstream ss;
    ss << std::fixed << std::setprecision(3) << seconds << " sec";
    return ss.str();
}

// Display a progress bar
void
printProgress(float progress) {
    std::cout << "[";
    int pos = progress_bar_width * progress;
    for (int i = 0; i < progress_bar_width; ++i) {
        if (i < pos)
            std::cout << "=";
        else if (i == pos)
            std::cout << ">";
        else
            std::cout << " ";
    }
    std::cout << "] " << std::fixed << std::setprecision(1) << (progress * 100.0) << "% ";

    // Add completion indicator
    if (progress >= 1.0) {
        std::cout << "DONE!" << std::endl;
    } else {
        std::cout << "\r";
        std::cout.flush();
    }
}

// Fill buffer with test pattern
void
initBuffer(void *addr, char pattern, size_t len) {
    memset(addr, pattern, len);
}

// // Verify buffer matches expected pattern
// bool
// verifyBuffer(void *addr, char expected, size_t len) {
//     unsigned char *buffer = (unsigned char *)addr;
//     for (size_t i = 0; i < len; i++) {
//         if (buffer[i] != expected) {
//             std::cout << "Buffer verification failed at offset " << i << ": expected "
//                       << (int)expected << ", found " << (int)buffer[i] << std::endl;
//             return false;
//         }
//     }
//     return true;
// }
} // namespace

// Helper class to manage request handles
class testHandleIterator {
private:
    bool reuse;
    bool set;
    bool prepare;
    bool release;
    nixlBackendReqH *handle;

public:
    testHandleIterator(bool _reuse) {
        reuse = _reuse;
        if (reuse) {
            prepare = true;
            release = false;
        } else {
            prepare = true;
            release = true;
        }
        handle = nullptr;
        set = false;
    }

    ~testHandleIterator() {
        /* Make sure that handler was released */
        assert(!set);
    }

    bool
    needPrep() {
        if (reuse) {
            if (!prepare) {
                return false;
            }
        }
        return true;
    }

    bool
    needRelease() {
        return release;
    }

    void
    isLast() {
        if (reuse) {
            release = true;
        }
    }

    void
    setHandle(nixlBackendReqH *_handle) {
        assert(!set);
        handle = _handle;
        set = true;
        if (reuse) {
            prepare = false;
        }
    }

    void
    unsetHandle() {
        assert(set);
        set = false;
    }

    nixlBackendReqH *&
    getHandle() {
        assert(set);
        return handle;
    }
};

class CxlExpTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        // Check if NUMA is available, skip test if not
        if (numa_available() < 0) {
            GTEST_SKIP() << "NUMA library not available, skipping test";
        }

        // Initialize the CXL engine
        engine = createEngine("Agent1");
        if (!engine) {
            GTEST_SKIP() << "CXL engine creation failed or no CXL devices detected";
        }
    }

    void
    TearDown() override {
        if (engine) {
            releaseEngine(engine);
            engine = nullptr;
        }
    }

    // Create a CXL Experimental Engine
    nixlBackendEngine *
    createEngine(std::string name) {
        nixlBackendEngine *cxl;
        nixlBackendInitParams init;
        nixl_b_params_t custom_params;

        init.enableProgTh = false;
        init.pthrDelay = 100;
        init.localAgent = name;
        init.customParams = &custom_params;
        init.type = "CXL_EXP";
        // init.syncMode = MUTEX;

        try {
            cxl = new nixlCxlExpEngine(&init);

            if (cxl->getInitErr()) {
                std::cout << "Failed to initialize CXL engine" << std::endl;
                delete cxl;
                return nullptr;
            }

            return cxl;
        }
        catch (const std::exception &e) {
            std::cerr << "Exception creating CXL engine: " << e.what() << std::endl;
            return nullptr;
        }
    }

    void
    releaseEngine(nixlBackendEngine *cxl) {
        delete cxl;
    }

    // Allocate a buffer for testing with page alignment
    void
    allocateBuffer(size_t len, void *&addr) {
        addr = aligned_alloc(4096, len); // Page-aligned allocation
        ASSERT_NE(addr, nullptr);
        memset(addr, 0, len);
    }

    // Release allocated buffer
    void
    releaseBuffer(void *&addr) {
        free(addr);
        addr = nullptr;
    }

    // Register memory with the CXL engine
    nixl_status_t
    allocateAndRegister(nixlBackendEngine *cxl, void *&addr, size_t len, nixlBackendMD *&md) {
        nixlBlobDesc desc;

        allocateBuffer(len, addr);

        desc.addr = (uintptr_t)addr;
        desc.len = len;
        desc.devId = 0; // Use default device ID

        return cxl->registerMem(desc, DRAM_SEG, md);
    }

    // Deregister memory with the CXL engine
    nixl_status_t
    deallocateAndDeregister(nixlBackendEngine *cxl, void *&addr, nixlBackendMD *&md) {
        nixl_status_t ret = cxl->deregisterMem(md);
        releaseBuffer(addr);
        return ret;
    }

    // Perform a memory transfer test with performance measurement
    void
    performTransfer(nixlBackendEngine *cxl,
                    nixl_meta_dlist_t &src_descs,
                    nixl_meta_dlist_t &dst_descs,
                    void *src_addr,
                    void *dst_addr,
                    size_t len,
                    nixl_xfer_op_t op,
                    testHandleIterator &hiter) {
        nixl_status_t ret;
        nixlTime::us_t time_start, time_end, time_duration;

        std::cout << "\t" << (op == NIXL_READ ? "READ" : "WRITE") << " from " << src_addr << " to "
                  << dst_addr << "\n";

        // Prepare the transfer request
        if (hiter.needPrep()) {
            nixlBackendReqH *new_handle = nullptr;
            ret = cxl->prepXfer(op, src_descs, dst_descs, "Agent1", new_handle);
            ASSERT_EQ(ret, NIXL_SUCCESS);
            hiter.setHandle(new_handle);
        }

        nixlBackendReqH *&handle = hiter.getHandle();

        // Post the transfer request and measure performance
        time_start = nixlTime::getUs();
        ret = cxl->postXfer(op, src_descs, dst_descs, "Agent1", handle);
        ASSERT_TRUE(ret == NIXL_SUCCESS || ret == NIXL_IN_PROG);

        // Check transfer status if needed
        int max_waits = 1000;
        int wait_count = 0;
        while (ret == NIXL_IN_PROG) {
            ret = cxl->checkXfer(handle);
            ASSERT_TRUE(ret == NIXL_SUCCESS || ret == NIXL_IN_PROG);

            if (wait_count++ > max_waits) {
                ADD_FAILURE() << "Transfer timed out after " << max_waits << " checks";
                break;
            }

            // Show progress
            if (wait_count % 10 == 0) {
                printProgress(std::min(1.0f, float(wait_count) / max_waits));
            }
        }
        time_end = nixlTime::getUs();
        time_duration = time_end - time_start;

        // Calculate performance metrics
        double data_gb = static_cast<double>(len) / gb_size;
        double seconds = us_to_s(time_duration);
        double gbps = data_gb / seconds;

        // Release the request handle if needed
        if (hiter.needRelease()) {
            hiter.unsetHandle();
            cxl->releaseReqH(handle);
        }

        // Verify data transfer
        cout << "\t\tData verification: " << flush;
        bool success = true;

        if (op == NIXL_READ) {
            // In READ operation, data is copied from dst_addr to src_addr
            unsigned char *src_buf = (unsigned char *)src_addr;
            unsigned char *dst_buf = (unsigned char *)dst_addr;
            for (size_t i = 0; i < len; i++) {
                if (src_buf[i] != dst_buf[i]) {
                    cout << "FAILED at position " << i << ", expected " << (int)dst_buf[i]
                         << ", got " << (int)src_buf[i] << endl;
                    success = false;
                    break;
                }
            }
        } else { // NIXL_WRITE
            // In WRITE operation, data is copied from src_addr to dst_addr
            unsigned char *src_buf = (unsigned char *)src_addr;
            unsigned char *dst_buf = (unsigned char *)dst_addr;
            for (size_t i = 0; i < len; i++) {
                if (dst_buf[i] != src_buf[i]) {
                    cout << "FAILED at position " << i << ", expected " << (int)src_buf[i]
                         << ", got " << (int)dst_buf[i] << endl;
                    success = false;
                    break;
                }
            }
        }

        ASSERT_TRUE(success);
        cout << "OK" << endl;

        // Print performance metrics
        std::cout << "\t\tTransfer completed in " << format_duration(time_duration) << std::endl;
        std::cout << "\t\tData size: " << std::fixed << std::setprecision(3) << data_gb << " GB"
                  << std::endl;
        std::cout << "\t\tBandwidth: " << std::fixed << std::setprecision(3) << gbps << " GB/s"
                  << std::endl;
    }

    nixlBackendEngine *engine = nullptr;
};

// Test local memory transfers within the same agent
TEST_F(CxlExpTest, LocalMemoryTransfer) {
    print_segment_title(phase_title("Intra-agent memory transfer test"));

    std::string agent1("Agent1");
    nixl_status_t ret;

    // Verify that the engine supports local transfers
    ASSERT_TRUE(engine->supportsLocal());

    // Connect to self for local transfers
    ret = engine->connect(agent1);
    ASSERT_EQ(ret, NIXL_SUCCESS);

    std::cout << "Local connection complete\n";

    // Number of transfer descriptors
    int desc_cnt = 16;
    // Size of a single descriptor
    size_t desc_size = default_transfer_size / desc_cnt;
    size_t len = desc_cnt * desc_size;

    void *addr1 = nullptr, *addr2 = nullptr;
    nixlBackendMD *lmd1 = nullptr, *lmd2 = nullptr;

    // Allocate and register memory regions
    ret = allocateAndRegister(engine, addr1, len, lmd1);
    ASSERT_EQ(ret, NIXL_SUCCESS);
    ret = allocateAndRegister(engine, addr2, len, lmd2);
    ASSERT_EQ(ret, NIXL_SUCCESS);

    // Convert metadata for local transfers
    nixlBackendMD *rmd2 = nullptr;
    ret = engine->loadLocalMD(lmd2, rmd2);
    ASSERT_EQ(ret, NIXL_SUCCESS);

    // Prepare descriptor lists
    nixl_meta_dlist_t src_descs(DRAM_SEG);
    nixl_meta_dlist_t dst_descs(DRAM_SEG);

    std::cout << "Populating descriptor lists" << std::endl;

    // Populate descriptor lists
    for (int i = 0; i < desc_cnt; i++) {
        nixlMetaDesc src_desc, dst_desc;

        src_desc.addr = (uintptr_t)addr1 + i * desc_size;
        src_desc.len = desc_size;
        src_desc.devId = 0;
        src_desc.metadataP = lmd1;
        src_descs.addDesc(src_desc);

        dst_desc.addr = (uintptr_t)addr2 + i * desc_size;
        dst_desc.len = desc_size;
        dst_desc.devId = 0;
        dst_desc.metadataP = rmd2;
        dst_descs.addDesc(dst_desc);

        printProgress(float(i + 1) / desc_cnt);
    }

    // Test READ and WRITE operations
    nixl_xfer_op_t ops[] = {NIXL_READ, NIXL_WRITE};
    nixlTime::us_t total_time = 0;
    double total_data_gb = 0;

    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[i]); i++) {
        print_segment_title(std::string(ops[i] == NIXL_READ ? "READ" : "WRITE") + " test (" +
                            std::to_string(default_num_transfers) + " iterations)");

        for (int k = 0; k < default_num_transfers; k++) {
            std::cout << "Iteration " << (k + 1) << "/" << default_num_transfers << std::endl;

            // Initialize data with different patterns for source and destination
            char src_pattern = 0xAA;
            char dst_pattern = 0x55;

            initBuffer(addr1, src_pattern, len);
            initBuffer(addr2, dst_pattern, len);

            // Perform transfer
            testHandleIterator hiter(false);
            performTransfer(engine, src_descs, dst_descs, addr1, addr2, len, ops[i], hiter);

            // Add to performance totals
            total_time += nixlTime::getUs(); // This isn't accurate - just a placeholder
            total_data_gb += static_cast<double>(len) / gb_size;
        }
    }

    // Test handle reuse
    print_segment_title(phase_title("Testing handle reuse"));
    testHandleIterator hiter(true);
    for (int k = 0; k < default_num_transfers; k++) {
        std::cout << "Iteration " << (k + 1) << "/" << default_num_transfers << std::endl;

        // Initialize data
        char src_pattern = 0xAA + k;
        char dst_pattern = 0x55 + k;

        initBuffer(addr1, src_pattern, len);
        initBuffer(addr2, dst_pattern, len);

        // Mark the last iteration
        if (k == default_num_transfers - 1) {
            hiter.isLast();
        }

        // Perform transfer
        performTransfer(engine, src_descs, dst_descs, addr1, addr2, len, NIXL_WRITE, hiter);
    }

    // Clean up
    engine->unloadMD(rmd2);
    ret = deallocateAndDeregister(engine, addr1, lmd1);
    ASSERT_EQ(ret, NIXL_SUCCESS);
    ret = deallocateAndDeregister(engine, addr2, lmd2);
    ASSERT_EQ(ret, NIXL_SUCCESS);

    engine->disconnect(agent1);
}

// Test cost estimation functionality
TEST_F(CxlExpTest, CostEstimation) {
    print_segment_title(phase_title("Transfer cost estimation test"));

    // Allocate memory and register it
    void *addr1 = nullptr, *addr2 = nullptr;
    nixlBackendMD *lmd1 = nullptr, *lmd2 = nullptr, *rmd2 = nullptr;
    size_t len = 1 * 1024 * 1024; // 1MB

    nixl_status_t ret = allocateAndRegister(engine, addr1, len, lmd1);
    ASSERT_EQ(ret, NIXL_SUCCESS);
    ret = allocateAndRegister(engine, addr2, len, lmd2);
    ASSERT_EQ(ret, NIXL_SUCCESS);

    // Convert metadata for local transfers
    ret = engine->loadLocalMD(lmd2, rmd2);
    ASSERT_EQ(ret, NIXL_SUCCESS);

    // Create descriptor lists
    nixl_meta_dlist_t src_descs(DRAM_SEG);
    nixl_meta_dlist_t dst_descs(DRAM_SEG);

    // Populate descriptor lists
    nixlMetaDesc src_desc, dst_desc;
    src_desc.addr = (uintptr_t)addr1;
    src_desc.len = len;
    src_desc.devId = 0;
    src_desc.metadataP = lmd1;
    src_descs.addDesc(src_desc);

    dst_desc.addr = (uintptr_t)addr2;
    dst_desc.len = len;
    dst_desc.devId = 0;
    dst_desc.metadataP = rmd2;
    dst_descs.addDesc(dst_desc);

    // Create a transfer request handle
    nixlBackendReqH *handle = nullptr;
    ret = engine->prepXfer(NIXL_WRITE, src_descs, dst_descs, "Agent1", handle);
    ASSERT_EQ(ret, NIXL_SUCCESS);

    // Estimate cost
    std::chrono::microseconds duration;
    std::chrono::microseconds err_margin;
    nixl_cost_t method;

    ret = engine->estimateXferCost(
        NIXL_WRITE, src_descs, dst_descs, "Agent1", handle, duration, err_margin, method);

    if (ret == NIXL_SUCCESS) {
        cout << "Cost estimation successful:" << endl;
        cout << "  Estimated duration: " << duration.count() << " microseconds" << endl;
        cout << "  Error margin: " << err_margin.count() << " microseconds" << endl;
        cout << "  Method: " << static_cast<int>(method) << endl;
    } else if (ret == NIXL_ERR_NOT_SUPPORTED) {
        cout << "Cost estimation not supported by this backend" << endl;
    } else {
        FAIL() << "Cost estimation failed with error: " << ret;
    }

    // Clean up
    engine->releaseReqH(handle);
    engine->unloadMD(rmd2);
    deallocateAndDeregister(engine, addr1, lmd1);
    deallocateAndDeregister(engine, addr2, lmd2);
}

// Test NUMA node detection and awareness
TEST_F(CxlExpTest, NumaAwareness) {
    print_segment_title(phase_title("NUMA awareness test"));

    // Get NUMA node count
    int max_node = numa_max_node();
    if (max_node < 0) {
        GTEST_SKIP() << "Failed to get maximum NUMA node, skipping NUMA awareness test";
    }

    std::cout << "System has " << (max_node + 1) << " NUMA nodes" << std::endl;

    // Try to allocate and register memory on each NUMA node
    for (int node = 0; node <= max_node; node++) {
        if (!numa_bitmask_isbitset(numa_nodes_ptr, node)) {
            std::cout << "NUMA node " << node << " is not available, skipping" << std::endl;
            continue;
        }

        std::cout << "Testing memory on NUMA node " << node << std::endl;

        // Allocate memory on the specific NUMA node
        size_t len = 1 * 1024 * 1024; // 1MB
        void *addr = nullptr;

        // Use numa_alloc_onnode for NUMA-specific allocation
        addr = numa_alloc_onnode(len, node);
        if (!addr) {
            std::cout << "Failed to allocate memory on NUMA node " << node << std::endl;
            continue;
        }

        // Register the NUMA-specific memory
        nixlBlobDesc desc;
        desc.addr = (uintptr_t)addr;
        desc.len = len;
        desc.devId = node; // Use node ID as device ID

        nixlBackendMD *md = nullptr;
        nixl_status_t ret = engine->registerMem(desc, DRAM_SEG, md);

        if (ret == NIXL_SUCCESS) {
            std::cout << "Successfully registered memory on NUMA node " << node << std::endl;

            // Check the NUMA node ID stored in metadata
            nixlCxlExpMetadata *cxl_md = dynamic_cast<nixlCxlExpMetadata *>(md);
            if (cxl_md) {
                std::cout << "NUMA node reported by metadata: " << cxl_md->numa_node_id
                          << std::endl;
                // Metadata should correctly identify the NUMA node
                EXPECT_EQ(cxl_md->numa_node_id, node);
            } else {
                ADD_FAILURE() << "Failed to cast to nixlCxlExpMetadata";
            }

            // Clean up
            engine->deregisterMem(md);
        } else {
            std::cout << "Failed to register memory on NUMA node " << node << " with error: " << ret
                      << std::endl;
        }

        // Free NUMA-allocated memory
        numa_free(addr, len);
    }
}

int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    // Parse any remaining command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "hi:s:n")) != -1) {
        switch (opt) {
        case 'h':
            std::cout << "Usage: " << argv[0] << " [-i iterations] [-s transfer_size] [-n]"
                      << std::endl;
            std::cout << "  -i iterations      Number of iterations for each test (default: "
                      << default_num_transfers << ")" << std::endl;
            std::cout << "  -s transfer_size   Size of each transfer in bytes (default: "
                      << default_transfer_size << ")" << std::endl;
            std::cout << "  -n                 Skip NUMA awareness test" << std::endl;
            std::cout << "  -h                 Show this help message" << std::endl;
            return 0;
        default:
            // Ignore unknown options - GTest has its own
            break;
        }
    }

    // Check if NUMA is available at the beginning
    if (numa_available() < 0) {
        std::cout << "NUMA library not available, some tests will be skipped" << std::endl;
    }

    return RUN_ALL_TESTS();
}
