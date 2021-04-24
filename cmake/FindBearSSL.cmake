#[=======================================================================[.rst:
FindBearSSL
-----------

Finds the BearSSL library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``BearSSL::BearSSL``
  The BearSSL library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``BearSSL_FOUND``
  True if the system has BearSSL.
``BearSSL_INCLUDE_DIRS``
  Include directories needed to use BearSSL.
``BearSSL_LIBRARIES``
  Libraries needed to link to BearSSL.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``BearSSL_INCLUDE_DIR``
  The directory containing ``bearssl.h``.
``BearSSL_LIBRARY``
  The path to the BearSSL library.

#]=======================================================================]
find_path(BearSSL_INCLUDE_DIR NAMES bearssl.h)
find_library(BearSSL_LIBRARY NAMES bearssl bearssls)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BearSSL
  FOUND_VAR BearSSL_FOUND
  REQUIRED_VARS
    BearSSL_LIBRARY
    BearSSL_INCLUDE_DIR
)

if(BearSSL_FOUND)
  set(BearSSL_LIBRARIES ${BearSSL_LIBRARY})
  set(BearSSL_INCLUDE_DIRS ${BearSSL_INCLUDE_DIR})
  if(NOT TARGET BearSSL::BearSSL)
    add_library(BearSSL::BearSSL UNKNOWN IMPORTED)
    set_target_properties(BearSSL::BearSSL PROPERTIES
      IMPORTED_LOCATION "${BearSSL_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${BearSSL_INCLUDE_DIRS}"
    )
  endif()
endif()

mark_as_advanced(
  BearSSL_INCLUDE_DIR
  BearSSL_LIBRARY
)
