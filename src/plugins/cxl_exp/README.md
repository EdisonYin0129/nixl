# CXL Experimental Plugin for NIXL

This plugin provides experimental support for CXL (Compute Express Link) memory devices in NIXL.

## Features

- NUMA-aware memory operations for CXL devices
- Automatic detection of CXL NUMA nodes
- Support for basic memory transfer operations

## Requirements

- Linux with NUMA support
- libnuma development package
- A system with CXL memory devices

## Configuration Options

The plugin supports the following configuration options:

- `numa_policy`: Memory policy for CXL operations (bind, preferred, interleave)
- `force_cxl_device`: Manually specify a CXL device instead of auto-detection

## Limitations

This is an experimental plugin and has the following limitations:

- Only supports local memory operations (no remote operations)
- No notification support
- Simple synchronous implementation
- Limited optimization for bandwidth
