cmake_minimum_required(VERSION 3.12)
project(DNSMonitor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)

# Find libpcap
pkg_check_modules(PCAP REQUIRED libpcap)

# Find libcurl
find_package(CURL REQUIRED)

# Find jsoncpp
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

# Find pybind11
find_package(pybind11 REQUIRED)

# Include directories
include_directories(${PCAP_INCLUDE_DIRS})
include_directories(${JSONCPP_INCLUDE_DIRS})

# Create the main library
add_library(dns_monitor_lib STATIC
    dns_monitor.cpp
    dns_monitor.h
)

# Link libraries
target_link_libraries(dns_monitor_lib 
    ${PCAP_LIBRARIES}
    ${CURL_LIBRARIES}
    ${JSONCPP_LIBRARIES}
    pthread
    curl
)

# Create Python module using pybind11
pybind11_add_module(dns_monitor_cpp
    python_bindings.cpp
)

target_link_libraries(dns_monitor_cpp PRIVATE 
    dns_monitor_lib
)

# Create standalone executable for testing
add_executable(dns_monitor_test
    main.cpp
)

target_link_libraries(dns_monitor_test 
    dns_monitor_lib
)

# Compiler flags
target_compile_definitions(dns_monitor_lib PRIVATE ${PCAP_CFLAGS_OTHER})
target_compile_definitions(dns_monitor_lib PRIVATE ${JSONCPP_CFLAGS_OTHER})

# Set optimization flags for release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(dns_monitor_lib PRIVATE -O3 -march=native)
endif()

# Install targets
install(TARGETS dns_monitor_lib DESTINATION lib)
install(FILES dns_monitor.h DESTINATION include)
install(TARGETS dns_monitor_test DESTINATION bin)
