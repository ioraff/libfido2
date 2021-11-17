# Copyright (c) 2021 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# BearSSL coordinates.
New-Variable -Name 'BEARSSL_URL' `
    -Value 'https://bearssl.org' -Option Constant
New-Variable -Name 'BEARSSL' -Value 'bearssl-0.6' -Option Constant

# libcbor coordinates.
New-Variable -Name 'LIBCBOR' -Value 'libcbor-0.8.0' -Option Constant
New-Variable -Name 'LIBCBOR_BRANCH' -Value 'v0.8.0' -Option Constant
New-Variable -Name 'LIBCBOR_GIT' -Value 'https://github.com/pjk/libcbor' `
    -Option Constant

# zlib coordinates.
New-Variable -Name 'ZLIB' -Value 'zlib-1.2.11' -Option Constant
New-Variable -Name 'ZLIB_BRANCH' -Value 'v1.2.11' -Option Constant
New-Variable -Name 'ZLIB_GIT' -Value 'https://github.com/madler/zlib' `
    -Option Constant

# Work directories.
New-Variable -Name 'BUILD' -Value "$PSScriptRoot\..\build" -Option Constant
New-Variable -Name 'OUTPUT' -Value "$PSScriptRoot\..\output" -Option Constant

# Prefixes.
New-Variable -Name 'STAGE' -Value "${BUILD}\${Arch}\${Type}" -Option Constant
New-Variable -Name 'PREFIX' -Value "${OUTPUT}\${Arch}\${Type}" -Option Constant

# Build flags.
if ("${Type}" -eq "dynamic") {
	New-Variable -Name 'RUNTIME' -Value '/MD' -Option Constant
	New-Variable -Name 'SHARED' -Value 'ON' -Option Constant
} else {
	New-Variable -Name 'RUNTIME' -Value '/MT' -Option Constant
	New-Variable -Name 'SHARED' -Value 'OFF' -Option Constant
}
New-Variable -Name 'CFLAGS_DEBUG' -Value "${RUNTIME}d /Zi /guard:cf /sdl" `
    -Option Constant
New-Variable -Name 'CFLAGS_RELEASE' -Value "${RUNTIME} /Zi /guard:cf /sdl" `
    -Option Constant
New-Variable -Name 'VCARCH' -Value @{x64="x64"; Win32="x86"; ARM64="x64_arm64"; ARM="x64_arm"} `
    -Option Constant
