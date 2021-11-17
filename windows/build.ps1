# Copyright (c) 2021 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

param(
	[string]$CMakePath = "C:\Program Files\CMake\bin\cmake.exe",
	[string]$GitPath = "C:\Program Files\Git\bin\git.exe",
	[string]$SevenZPath = "C:\Program Files\7-Zip\7z.exe",
	[string]$VSWherePath = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe",
	[string]$WinSDK = "",
	[string]$Config = "Release",
	[string]$Arch = "x64",
	[string]$Type = "dynamic",
	[string]$Fido2Flags = ""
)

$ErrorView = "NormalView"
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

. "$PSScriptRoot\const.ps1"

Function ExitOnError() {
	if ($LastExitCode -ne 0) {
		throw "A command exited with status $LastExitCode"
	}
}

Function GitClone(${REPO}, ${BRANCH}, ${DIR}) {
	Write-Host "Cloning ${REPO}..."
	& $Git -c advice.detachedHead=false clone --quiet --depth=1 `
	    --branch "${BRANCH}" "${REPO}" "${DIR}"
	Write-Host "${REPO}'s ${BRANCH} HEAD is:"
	& $Git -C "${DIR}" show -s HEAD
}

# Find Git.
$Git = $(Get-Command git -ErrorAction Ignore | `
    Select-Object -ExpandProperty Source)
if ([string]::IsNullOrEmpty($Git)) {
	$Git = $GitPath
}
if (-Not (Test-Path $Git)) {
	throw "Unable to find Git at $Git"
}

# Find CMake.
$CMake = $(Get-Command cmake -ErrorAction Ignore | `
    Select-Object -ExpandProperty Source)
if ([string]::IsNullOrEmpty($CMake)) {
	$CMake = $CMakePath
}
if (-Not (Test-Path $CMake)) {
	throw "Unable to find CMake at $CMake"
}

# Find 7z.
$SevenZ = $(Get-Command 7z -ErrorAction Ignore | `
    Select-Object -ExpandProperty Source)
if ([string]::IsNullOrEmpty($SevenZ)) {
	$SevenZ = $SevenZPath
}
if (-Not (Test-Path $SevenZ)) {
	throw "Unable to find 7z at $SevenZ"
}

# Find VSWhere.
$VSWhere = $(Get-Command vswhere -ErrorAction Ignore | `
    Select-Object -ExpandProperty Source)
if ([string]::IsNullOrEmpty($VSWhere)) {
	$VSWhere = $VSWherePath
}
if (-Not (Test-Path $VSWhere)) {
	throw "Unable to find VSWhere at $VSWhere"
}

# Override CMAKE_SYSTEM_VERSION if $WinSDK is set.
if (-Not ([string]::IsNullOrEmpty($WinSDK))) {
	$CMAKE_SYSTEM_VERSION = "-DCMAKE_SYSTEM_VERSION='$WinSDK'"
} else {
	$CMAKE_SYSTEM_VERSION = ''
}

Write-Host "WinSDK: $WinSDK"
Write-Host "Config: $Config"
Write-Host "Arch: $Arch"
Write-Host "Type: $Type"
Write-Host "Git: $Git"
Write-Host "CMake: $CMake"
Write-Host "7z: $SevenZ"
Write-Host "VSWhere: $VSWhere"

& $VSWhere -property installationPath | New-Variable -Name 'VSPREFIX' -Option Constant

# Create build directories.
New-Item -Type Directory "${BUILD}" -Force
New-Item -Type Directory "${BUILD}\${Arch}" -Force
New-Item -Type Directory "${BUILD}\${Arch}\${Type}" -Force
New-Item -Type Directory "${STAGE}\${BEARSSL}" -Force
New-Item -Type Directory "${STAGE}\${LIBCBOR}" -Force
New-Item -Type Directory "${STAGE}\${ZLIB}" -Force

# Create output directories.
New-Item -Type Directory "${OUTPUT}" -Force
New-Item -Type Directory "${OUTPUT}\${Arch}" -Force
New-Item -Type Directory "${OUTPUT}\${Arch}\${Type}" -force

# Fetch and verify dependencies.
Push-Location ${BUILD}
try {
	if (-Not (Test-Path .\${BEARSSL})) {
		if (-Not (Test-Path .\${BEARSSL}.tar.gz -PathType leaf)) {
			Invoke-WebRequest ${BEARSSL_URL}/${BEARSSL}.tar.gz `
			    -OutFile .\${BEARSSL}.tar.gz
		}

		& $SevenZ e .\${BEARSSL}.tar.gz
		& $SevenZ x .\${BEARSSL}.tar
		Remove-Item -Force .\${BEARSSL}.tar
	}
	if (-Not (Test-Path .\${LIBCBOR})) {
		GitClone "${LIBCBOR_GIT}" "${LIBCBOR_BRANCH}" ".\${LIBCBOR}"
	}
	if (-Not (Test-Path .\${ZLIB})) {
		GitClone "${ZLIB_GIT}" "${ZLIB_BRANCH}" ".\${ZLIB}"
	}
} catch {
	throw "Failed to fetch and verify dependencies"
} finally {
	Pop-Location
}

# Build BearSSL.
Push-Location ${STAGE}\${BEARSSL}
try {
	New-Item -Type Directory ${PREFIX}\include, ${PREFIX}\lib

	Push-Location ..\..\..\${BEARSSL}
	& cmd /c ("""${VSPREFIX}\VC\Auxiliary\Build\vcvarsall.bat"" $(${VCARCH}.${Arch}) && " +
		"nmake lib CFLAGS=""${FLAGS} -nologo -Zi -O2"" BUILD=$((Get-Location -Stack).Peek())")
	Copy-Item inc/*.h -Destination "${PREFIX}\include"
	Pop-Location

	Copy-Item "bearssls.lib" -Destination "${PREFIX}\lib"
} catch {
	throw "Failed to build BearSSL"
} finally {
	Pop-Location
}

# Build libcbor.
Push-Location ${STAGE}\${LIBCBOR}
try {
	& $CMake ..\..\..\${LIBCBOR} -A "${Arch}" `
	    -DWITH_EXAMPLES=OFF `
	    -DBUILD_SHARED_LIBS="${SHARED}" `
	    -DCMAKE_C_FLAGS_DEBUG="${CFLAGS_DEBUG}" `
	    -DCMAKE_C_FLAGS_RELEASE="${CFLAGS_RELEASE}" `
	    -DCMAKE_INSTALL_PREFIX="${PREFIX}" "${CMAKE_SYSTEM_VERSION}"; `
	    ExitOnError
	& $CMake --build . --config ${Config} --verbose; ExitOnError
	& $CMake --build . --config ${Config} --target install --verbose; `
	    ExitOnError
} catch {
	throw "Failed to build libcbor"
} finally {
	Pop-Location
}

# Build zlib.
Push-Location ${STAGE}\${ZLIB}
try {
	& $CMake ..\..\..\${ZLIB} -A "${Arch}" `
	    -DBUILD_SHARED_LIBS="${SHARED}" `
	    -DCMAKE_C_FLAGS_DEBUG="${CFLAGS_DEBUG}" `
	    -DCMAKE_C_FLAGS_RELEASE="${CFLAGS_RELEASE}" `
	    -DCMAKE_INSTALL_PREFIX="${PREFIX}" "${CMAKE_SYSTEM_VERSION}"; `
	    ExitOnError
	& $CMake --build . --config ${Config} --verbose; ExitOnError
	& $CMake --build . --config ${Config} --target install --verbose; `
	    ExitOnError
	# Patch up zlib's resulting names when built with --config Debug.
	if ("${Config}" -eq "Debug") {
		if ("${Type}" -eq "Dynamic") {
			Copy-Item "${PREFIX}/lib/zlibd.lib" `
			    -Destination "${PREFIX}/lib/zlib.lib" -Force
			Copy-Item "${PREFIX}/bin/zlibd1.dll" `
			    -Destination "${PREFIX}/bin/zlib1.dll" -Force
		} else {
			Copy-Item "${PREFIX}/lib/zlibstaticd.lib" `
			    -Destination "${PREFIX}/lib/zlib.lib" -Force
		}
	}
} catch {
	throw "Failed to build zlib"
} finally {
	Pop-Location
}

# Build libfido2.
Push-Location ${STAGE}
try {
	# C4244 and C4267 are false-positive warnings from BearSSL
	# headers. C4702 (unreachable code) is due to all cases
	# commented out in tools/util.c for writing public keys (lack
	# of support from BearSSL). C6001 (use of uninitialized memory)
	# is false-positive for the hash variable in rs1_verify_sig()
	# and rs256_verify_sig(). Disable for now.
	& $CMake ..\..\.. -A "${Arch}" `
	    -DCMAKE_BUILD_TYPE="${Config}" `
	    -DBUILD_SHARED_LIBS="${SHARED}" `
	    -DCMAKE_PREFIX_PATH="${PREFIX}" `
	    -DCMAKE_C_FLAGS_DEBUG="${CFLAGS_DEBUG} ${Fido2Flags} /wd4244 /wd4267 /wd4702 /wd6001" `
	    -DCMAKE_C_FLAGS_RELEASE="${CFLAGS_RELEASE} ${Fido2Flags} /wd4244 /wd4267 /wd4702 /wd6001" `
	    -DCMAKE_INSTALL_PREFIX="${PREFIX}" "${CMAKE_SYSTEM_VERSION}"; `
	    ExitOnError
	& $CMake --build . --config ${Config} --verbose; ExitOnError
	& $CMake --build . --config ${Config} --target install --verbose; `
	    ExitOnError
} catch {
	throw "Failed to build libfido2"
} finally {
	Pop-Location
}
