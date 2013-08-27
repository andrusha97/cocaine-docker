CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(COCAINE-DOCKER-PLUGIN)

SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

FIND_PACKAGE(Boost 1.40.0
    REQUIRED COMPONENTS
        system
        filesystem)

INCLUDE(cmake/locate_library.cmake)

LOCATE_LIBRARY(LIBCOCAINE "cocaine/context.hpp" "cocaine-core")
LOCATE_LIBRARY(LIBEV "ev++.h" "ev" "libev")
LOCATE_LIBRARY(LIBMSGPACK "msgpack.hpp" "msgpack")
LOCATE_LIBRARY(LIBCURL "curl/curl.h" "curl")

INCLUDE_DIRECTORIES(
    ${Boost_INCLUDE_DIRS}
    ${LIBCOCAINE_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBCURL_INCLUDE_DIRS}
    ${LIBMSGPACK_INCLUDE_DIRS})

LINK_DIRECTORIES(
    ${Boost_LIBRARY_DIRS}
    ${LIBCOCAINE_LIBRARY_DIRS}
    ${LIBEV_LIBRARY_DIRS}
    ${LIBCURL_LIBRARY_DIRS}
    ${LIBMSGPACK_LIBRARY_DIRS})

ADD_LIBRARY(docker MODULE
    module
    isolate
    docker_client
    http)

TARGET_LINK_LIBRARIES(docker
    cocaine-core
    curl
    boost_system)

SET_TARGET_PROPERTIES(docker PROPERTIES
    PREFIX ""
    SUFFIX ".cocaine-plugin"
    COMPILE_FLAGS "-std=c++0x")

INSTALL(
    TARGETS docker
    LIBRARY DESTINATION lib/cocaine
    COMPONENT runtime)