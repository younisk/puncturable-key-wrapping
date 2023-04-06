cmake_minimum_required(VERSION 3.23)
project(puncturable_key_wrapping_cpp)

set(CMAKE_CXX_STANDARD 14)


set(SOURCE_FILES main.cpp)

add_executable(PKW_run ${SOURCE_FILES})
include_directories(puncturable-key-wrapping-cpp_lib)
add_subdirectory(puncturable-key-wrapping-cpp_lib)

target_link_libraries(PKW_run PKWLib)


add_subdirectory(puncturable-key-wrapping-cpp_tests)
add_subdirectory(demo)