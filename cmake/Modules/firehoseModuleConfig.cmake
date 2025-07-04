INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_FIREHOSEMODULE firehoseModule)

FIND_PATH(
    FIREHOSEMODULE_INCLUDE_DIRS
    NAMES firehoseModule/api.h
    HINTS $ENV{FIREHOSEMODULE_DIR}/include
        ${PC_FIREHOSEMODULE_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    FIREHOSEMODULE_LIBRARIES
    NAMES gnuradio-firehoseModule
    HINTS $ENV{FIREHOSEMODULE_DIR}/lib
        ${PC_FIREHOSEMODULE_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/firehoseModuleTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(FIREHOSEMODULE DEFAULT_MSG FIREHOSEMODULE_LIBRARIES FIREHOSEMODULE_INCLUDE_DIRS)
MARK_AS_ADVANCED(FIREHOSEMODULE_LIBRARIES FIREHOSEMODULE_INCLUDE_DIRS)
