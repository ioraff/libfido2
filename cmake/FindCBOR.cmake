#[=======================================================================[.rst:
FindCBOR
--------

Finds the libcbor library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``CBOR::CBOR``
  The libcbor library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``CBOR_FOUND``
  True if the system has libcbor.
``CBOR_VERSION``
  The version of the libcbor which was found.
``CBOR_INCLUDE_DIRS``
  Include directories needed to use libcbor.
``CBOR_LIBRARIES``
  Libraries needed to link to libcbor.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``CBOR_INCLUDE_DIR``
  The directory containing ``cbor.h``.
``CBOR_LIBRARY``
  The path to the libcbor library.

#]=======================================================================]
find_package(PkgConfig QUIET)
pkg_check_modules(PC_CBOR QUIET libcbor)

find_path(CBOR_INCLUDE_DIR
  NAMES cbor.h
  PATHS ${PC_CBOR_INCLUDE_DIRS}
)
find_library(CBOR_LIBRARY
  NAMES cbor
  PATHS ${PC_CBOR_LIBRARY_DIRS}
)

set(CBOR_VERSION ${PC_CBOR_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CBOR
  FOUND_VAR CBOR_FOUND
  REQUIRED_VARS
    CBOR_LIBRARY
    CBOR_INCLUDE_DIR
  VERSION_VAR CBOR_VERSION
)

if(CBOR_FOUND)
  set(CBOR_LIBRARIES ${CBOR_LIBRARY})
  set(CBOR_INCLUDE_DIRS ${CBOR_INCLUDE_DIR})
  set(CBOR_DEFINITIONS ${PC_CBOR_CFLAGS_OTHER})
  if(NOT TARGET CBOR::CBOR)
    add_library(CBOR::CBOR UNKNOWN IMPORTED)
    set_target_properties(CBOR::CBOR PROPERTIES
      IMPORTED_LOCATION "${CBOR_LIBRARY}"
      INTERFACE_COMPILE_OPTIONS "${PC_CBOR_CFLAGS_OTHER}"
      INTERFACE_INCLUDE_DIRECTORIES "${CBOR_INCLUDE_DIRS}"
    )
  endif()
endif()

mark_as_advanced(
  CBOR_INCLUDE_DIR
  CBOR_LIBRARY
)
