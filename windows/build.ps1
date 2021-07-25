param(
	[string]$CMakePath = "C:\Program Files\CMake\bin\cmake.exe",
	[string]$GitPath = "C:\Program Files\Git\bin\git.exe",
	[string]$SevenZPath = "C:\Program Files\7-Zip\7z.exe",
	[string]$VSWherePath = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe",
	[string]$WinSDK = "",
	[string]$Fido2Flags = ""
)

$ErrorView = "NormalView"
$ErrorActionPreference = "Continue"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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

# Find CMake.
$CMake = $(Get-Command cmake -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($CMake)) {
	$CMake = $CMakePath
}

# Find Git.
$Git = $(Get-Command git -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($Git)) {
	$Git = $GitPath
}

# Find 7z.
$SevenZ = $(Get-Command 7z -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($SevenZ)) {
	$SevenZ = $SevenZPath
}

# Find VSWhere.
$VSWhere = $(Get-Command vswhere -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($VSWhere)) {
	$VSWhere = $VSWherePath
}

# Override CMAKE_SYSTEM_VERSION if $WinSDK is set.
if(-Not ([string]::IsNullOrEmpty($WinSDK))) {
	$CMAKE_SYSTEM_VERSION = "-DCMAKE_SYSTEM_VERSION='$WinSDK'"
} else {
	$CMAKE_SYSTEM_VERSION = ''
}

if(-Not (Test-Path $CMake)) {
	throw "Unable to find CMake at $CMake"
}

if(-Not (Test-Path $Git)) {
	throw "Unable to find Git at $Git"
}

if(-Not (Test-Path $SevenZ)) {
	throw "Unable to find 7z at $SevenZ"
}

if(-Not (Test-Path $VSWhere)) {
	throw "Unable to find VSWhere at $VSWhere"
}

Write-Host "Git: $Git"
Write-Host "CMake: $CMake"
Write-Host "7z: $SevenZ"
Write-Host "VSWhere: $VSWhere"

& $VSWhere -property installationPath | New-Variable -Name 'VSPREFIX' -Option Constant

New-Item -Type Directory ${BUILD}
New-Item -Type Directory ${BUILD}\32
New-Item -Type Directory ${BUILD}\32\dynamic
New-Item -Type Directory ${BUILD}\32\static
New-Item -Type Directory ${BUILD}\64
New-Item -Type Directory ${BUILD}\64\dynamic
New-Item -Type Directory ${BUILD}\64\static
New-Item -Type Directory ${OUTPUT}
New-Item -Type Directory ${OUTPUT}\pkg\Win64\Release\v142\dynamic
New-Item -Type Directory ${OUTPUT}\pkg\Win32\Release\v142\dynamic
New-Item -Type Directory ${OUTPUT}\pkg\Win64\Release\v142\static
New-Item -Type Directory ${OUTPUT}\pkg\Win32\Release\v142\static

Push-Location ${BUILD}

try {
	if (Test-Path .\${BEARSSL}) {
		Remove-Item .\${BEARSSL} -Recurse -ErrorAction Stop
	}

	if(-Not (Test-Path .\${BEARSSL}.tar.gz -PathType leaf)) {
		Invoke-WebRequest ${BEARSSL_URL}/${BEARSSL}.tar.gz `
			-OutFile .\${BEARSSL}.tar.gz
	}

	& $SevenZ e .\${BEARSSL}.tar.gz
	& $SevenZ x .\${BEARSSL}.tar
	Remove-Item -Force .\${BEARSSL}.tar

	if(-Not (Test-Path .\${LIBCBOR})) {
		Write-Host "Cloning ${LIBCBOR}..."
		& $Git clone --branch ${LIBCBOR_BRANCH} ${LIBCBOR_GIT} `
			.\${LIBCBOR}
	}

	if(-Not (Test-Path .\${ZLIB})) {
		Write-Host "Cloning ${ZLIB}..."
		& $Git clone --branch ${ZLIB_BRANCH} ${ZLIB_GIT} `
			.\${ZLIB}
	}
} catch {
	throw "Failed to fetch and verify dependencies"
} finally {
	Pop-Location
}

Function Build(${OUTPUT}, ${GENERATOR}, ${ARCH}, ${SHARED}, ${FLAGS}) {
	New-Item -Type Directory ${OUTPUT}\include, ${OUTPUT}\lib

	if(-Not (Test-Path .\${BEARSSL})) {
		New-Item -Type Directory .\${BEARSSL} -ErrorAction Stop
	}

	Push-Location ..\..\${BEARSSL}
	& cmd /c ("""${VSPREFIX}\VC\Auxiliary\Build\vcvarsall.bat"" $(${ARCH} -eq ""Win32"" ? ""x86"" : ${ARCH}) && " +
		"nmake lib CFLAGS=""${FLAGS} -nologo -Zi -O2"" BUILD=$((Get-Location -Stack).Peek())\${BEARSSL}")
	Copy-Item inc/*.h -Destination "${OUTPUT}\include"
	Pop-Location

	Push-Location .\${BEARSSL}
	Copy-Item "bearssls.lib" -Destination "${OUTPUT}\lib"
	Pop-Location

	if (-Not (Test-Path .\${LIBCBOR})) {
		New-Item -Type Directory .\${LIBCBOR} -ErrorAction Stop
	}

	Push-Location .\${LIBCBOR}
	& $CMake ..\..\..\${LIBCBOR} -G "${GENERATOR}" -A "${ARCH}" `
		-DBUILD_SHARED_LIBS="${SHARED}" `
		-DCMAKE_C_FLAGS_RELEASE="${FLAGS} /Zi /guard:cf /sdl" `
		-DCMAKE_INSTALL_PREFIX="${OUTPUT}" "${CMAKE_SYSTEM_VERSION}"
	& $CMake --build . --config Release --verbose
	& $CMake --build . --config Release --target install --verbose
	Pop-Location

	if(-Not (Test-Path .\${ZLIB})) {
		New-Item -Type Directory .\${ZLIB} -ErrorAction Stop
	}

	Push-Location .\${ZLIB}
	& $CMake ..\..\..\${ZLIB} -G "${GENERATOR}" -A "${ARCH}" `
		-DBUILD_SHARED_LIBS="${SHARED}" `
		-DCMAKE_C_FLAGS_RELEASE="${FLAGS} /Zi /guard:cf /sdl" `
		-DCMAKE_INSTALL_PREFIX="${OUTPUT}" "${CMAKE_SYSTEM_VERSION}"
	& $CMake --build . --config Release --verbose
	& $CMake --build . --config Release --target install --verbose
	Pop-Location

        # C6001 (use of uninitialized memory) gives false-positive
        # for hash variable in assert.c:fido_verify_sig_rs256.
	# Disable for now.
	& $CMake ..\..\.. -G "${GENERATOR}" -A "${ARCH}" `
		-DBUILD_SHARED_LIBS="${SHARED}" `
		-DCMAKE_PREFIX_PATH="${OUTPUT}" `
		-DCMAKE_C_FLAGS_RELEASE="${FLAGS} /Zi /guard:cf /sdl /wd4244 /wd4267 /wd4702 /wd6001 ${Fido2Flags}" `
		-DCMAKE_INSTALL_PREFIX="${OUTPUT}" "${CMAKE_SYSTEM_VERSION}"
	& $CMake --build . --config Release --verbose
	& $CMake --build . --config Release --target install --verbose
}

Function Package-Headers() {
	Copy-Item "${OUTPUT}\64\dynamic\include" -Destination "${OUTPUT}\pkg" `
		-Recurse -ErrorAction Stop
}

Function Package-Dynamic(${SRC}, ${DEST}) {
	Copy-Item "${SRC}\bin\cbor.dll" "${DEST}" -ErrorAction Stop
	Copy-Item "${SRC}\lib\cbor.lib" "${DEST}" -ErrorAction Stop
	Copy-Item "${SRC}\bin\zlib1.dll" "${DEST}" -ErrorAction Stop
	Copy-Item "${SRC}\lib\zlib.lib" "${DEST}" -ErrorAction Stop
	Copy-Item "${SRC}\lib\bearssls.lib" "${DEST}" -ErrorAction Stop
	Copy-Item "${SRC}\bin\fido2.dll" "${DEST}" -ErrorAction Stop
	Copy-Item "${SRC}\lib\fido2.lib" "${DEST}" -ErrorAction Stop
}

Function Package-Static(${SRC}, ${DEST}) {
	Copy-Item "${SRC}/lib/cbor.lib" "${DEST}" -ErrorAction Stop
	Copy-Item "${SRC}/lib/zlib.lib" "${DEST}" -ErrorAction Stop
	Copy-Item "${SRC}/lib/bearssls.lib" "${DEST}" -ErrorAction Stop
	Copy-Item "${SRC}/lib/fido2_static.lib" "${DEST}/fido2.lib" `
		-ErrorAction Stop
}

Function Package-PDBs(${SRC}, ${DEST}) {
	Copy-Item "${SRC}\${LIBCBOR}\src\cbor.dir\Release\vc142.pdb" `
		"${DEST}\cbor.pdb" -ErrorAction Stop
	Copy-Item "${SRC}\${ZLIB}\zlib.dir\Release\vc142.pdb" `
		"${DEST}\zlib.pdb" -ErrorAction Stop
	Copy-Item "${SRC}\src\fido2_shared.dir\Release\vc142.pdb" `
		"${DEST}\fido2.pdb" -ErrorAction Stop
}

Function Package-Tools(${SRC}, ${DEST}) {
	#Copy-Item "${SRC}\tools\Release\fido2-assert.exe" `
	#	"${DEST}\fido2-assert.exe" -ErrorAction stop
	Copy-Item "${SRC}\tools\Release\fido2-cred.exe" `
		"${DEST}\fido2-cred.exe" -ErrorAction stop
	Copy-Item "${SRC}\tools\Release\fido2-token.exe" `
		"${DEST}\fido2-token.exe" -ErrorAction stop
}

Push-Location ${BUILD}\64\dynamic
Build ${OUTPUT}\64\dynamic "Visual Studio 16 2019" "x64" "ON" "/MD"
Pop-Location
Push-Location ${BUILD}\32\dynamic
Build ${OUTPUT}\32\dynamic "Visual Studio 16 2019" "Win32" "ON" "/MD"
Pop-Location

Push-Location ${BUILD}\64\static
Build ${OUTPUT}\64\static "Visual Studio 16 2019" "x64" "OFF" "/MT"
Pop-Location
Push-Location ${BUILD}\32\static
Build ${OUTPUT}\32\static "Visual Studio 16 2019" "Win32" "OFF" "/MT"
Pop-Location

Package-Headers

Package-Dynamic ${OUTPUT}\64\dynamic ${OUTPUT}\pkg\Win64\Release\v142\dynamic
Package-PDBs ${BUILD}\64\dynamic ${OUTPUT}\pkg\Win64\Release\v142\dynamic
Package-Tools ${BUILD}\64\dynamic ${OUTPUT}\pkg\Win64\Release\v142\dynamic

Package-Dynamic ${OUTPUT}\32\dynamic ${OUTPUT}\pkg\Win32\Release\v142\dynamic
Package-PDBs ${BUILD}\32\dynamic ${OUTPUT}\pkg\Win32\Release\v142\dynamic
Package-Tools ${BUILD}\32\dynamic ${OUTPUT}\pkg\Win32\Release\v142\dynamic

Package-Static ${OUTPUT}\64\static ${OUTPUT}\pkg\Win64\Release\v142\static
Package-Static ${OUTPUT}\32\static ${OUTPUT}\pkg\Win32\Release\v142\static
