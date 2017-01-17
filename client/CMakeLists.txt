cmake_minimum_required(VERSION 3.6)
set(CMAKE_C_STANDARD 11)

project(biar-3-so)

set(SOURCE_FILES main.c ../common.h ../common.c)

set(CMAKE_C_FLAGS "-lssl -lcrypto")

add_executable(client ${SOURCE_FILES})