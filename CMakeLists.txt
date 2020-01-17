cmake_minimum_required(VERSION 3.15)
project(feuerwand C)

set(CMAKE_C_STANDARD 99)

add_executable(feuerwand main.c)
target_link_libraries(feuerwand netfilter_queue)
