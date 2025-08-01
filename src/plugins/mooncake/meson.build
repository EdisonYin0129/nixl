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

cpp = meson.get_compiler('cpp')
mooncake_lib = cpp.find_library('transfer_engine')

compile_flags = []

if 'Mooncake' in static_plugins
    mooncake_backend_lib = static_library('Mooncake',
               'mooncake_backend.cpp', 'mooncake_backend.h', 'mooncake_plugin.cpp',
               dependencies: [nixl_infra, serdes_interface, mooncake_lib, cuda_dep],
               include_directories: nixl_inc_dirs,
               install: false,
               cpp_args : compile_flags,
               name_prefix: 'libplugin_')  # Custom prefix for plugin libraries
else
    mooncake_backend_lib = shared_library('Mooncake',
               'mooncake_backend.cpp', 'mooncake_backend.h', 'mooncake_plugin.cpp',
               dependencies: [nixl_infra, serdes_interface, mooncake_lib, cuda_dep],
               include_directories: [nixl_inc_dirs, utils_inc_dirs],
               install: true,
               cpp_args : compile_flags + ['-fPIC'],
               name_prefix: 'libplugin_',  # Custom prefix for plugin libraries
               install_dir: plugin_install_dir,
               install_rpath: '$ORIGIN/..')

    if get_option('buildtype') == 'debug'
        run_command('sh', '-c',
                    'echo "Mooncake=' + mooncake_backend_lib.full_path() + '" >> ' + plugin_build_dir + '/pluginlist',
                    check: true
                )
    endif
endif

mooncake_backend_interface = declare_dependency(link_with: mooncake_backend_lib)
