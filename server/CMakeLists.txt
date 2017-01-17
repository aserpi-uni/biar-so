cmake_minimum_required(VERSION 3.6)
set(CMAKE_C_STANDARD 11)


project(biar-3-so)

set(SOURCE_FILES main.c ../common.h board.h message.h user.h board.c message.c user.c ../common.c)
configure_file(ssl/server.crt ssl/server.crt COPYONLY)
configure_file(ssl/server.key ssl/server.key COPYONLY)

set(CMAKE_C_FLAGS "-lssl -lcrypto")

add_executable(server ${SOURCE_FILES})