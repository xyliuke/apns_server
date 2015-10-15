cmake_minimum_required(VERSION 3.3)
project(apns_server)

include_directories(.)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp apns.cpp apns.h)
add_executable(apns_server ${SOURCE_FILES})
TARGET_LINK_LIBRARIES(apns_server libssl.a libcrypto.a)