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

# Get libnuma dependency
cc = meson.get_compiler('cpp')
libnuma_dep = cc.find_library('numa', required : false)

if not libnuma_dep.found()
  warning('libnuma not found, CXL experimental plugin will not be built')
else
  if 'CXL_EXP' in static_plugins
      cxl_exp_backend_lib = static_library('CXL_EXP',
                 'cxl_exp_backend.cpp', 'cxl_exp_backend.h', 'cxl_exp_plugin.cpp',
                 dependencies: [nixl_infra, libnuma_dep, nixl_common_dep],
                 include_directories: [nixl_inc_dirs, utils_inc_dirs],
                 install: false,
                 cpp_args : ['-DSTATIC_PLUGIN_CXL_EXP'],
                 name_prefix: 'libplugin_')  # Custom prefix for plugin libraries
  else
      cxl_exp_backend_lib = shared_library('CXL_EXP',
                 'cxl_exp_backend.cpp', 'cxl_exp_backend.h', 'cxl_exp_plugin.cpp',
                 dependencies: [nixl_infra, libnuma_dep, nixl_common_dep],
                 include_directories: [nixl_inc_dirs, utils_inc_dirs],
                 install: true,
                 cpp_args : ['-fPIC'],
                 name_prefix: 'libplugin_',  # Custom prefix for plugin libraries
                 install_dir: plugin_install_dir)

      # Write to pluginlist in any build type, not just debug
      run_command('sh', '-c',
                'echo "CXL_EXP=' + cxl_exp_backend_lib.full_path() + '" >> ' + plugin_build_dir + '/pluginlist',
                check: true
            )
  endif

  cxl_exp_backend_interface = declare_dependency(link_with: cxl_exp_backend_lib)
endif
