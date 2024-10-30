cmake_minimum_required(VERSION 3.20)
project(PswdCrakerMultiThread)

set(CMAKE_CXX_STANDARD 20)

add_executable(PswdCrakerMultiThread main.cpp
        HashFactory.cpp
        HashFactory.h)

# Link the crypt library
target_link_libraries(PswdCrakerMultiThread PRIVATE crypt)
