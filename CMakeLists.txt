cmake_minimum_required(VERSION 3.6)
project(biar_3_so)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp)
add_executable(biar_3_so ${SOURCE_FILES})