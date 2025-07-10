# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Check for libnuma dependency
cc = meson.get_compiler('cpp')
libnuma_dep = cc.find_library('numa', required: false)

if not libnuma_dep.found()
    warning('libnuma not found, CXL experimental plugin tests will not be built')
else
    # Find GTest directly instead of using the undefined gtest_dep variable
    gtest_lib = dependency('gtest', required: false)
    if not gtest_lib.found()
        # If not found through pkg-config, try to find the library directly
        gtest_lib = cc.find_library('gtest', required: true)
    endif

    # Include the plugin source directory to access the header files
    cxl_plugin_inc = include_directories('../../../../src/plugins/cxl_exp')
    
    # Get the CXL experimental plugin sources - either directly from the plugin or link to the built library
    cxl_plugin_dir = meson.project_source_root() / 'src' / 'plugins' / 'cxl_exp'
    cxl_plugin_sources = [
        cxl_plugin_dir / 'cxl_exp_backend.cpp',
        cxl_plugin_dir / 'cxl_exp_plugin.cpp'
    ]

    # Build the test executable with the plugin sources
    nixl_cxl_exp_test = executable('nixl_cxl_exp_test',
                                  'nixl_cxl_exp_test.cpp',
                                  cxl_plugin_sources,
                                  dependencies: [nixl_infra, libnuma_dep, nixl_common_dep, gtest_lib],
                                  include_directories: [nixl_inc_dirs, utils_inc_dirs, cxl_plugin_inc],
                                  cpp_args: ['-DGTEST_HAS_PTHREAD=1', '-DSTATIC_PLUGIN_CXL_EXP'])

    test('cxl_exp_test', nixl_cxl_exp_test, timeout: 120)
endif
