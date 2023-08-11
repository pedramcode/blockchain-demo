cmake_minimum_required(VERSION 3.20)

set(CMAKE_CXX_STANDARD 17)
project(blockchain LANGUAGES CXX VERSION 0.0.1)
file(GLOB_RECURSE SOURCES ${CMAKE_SOURCE_DIR}/src/*.cc)
set(CMAKE_CXX_COMPILE_FEATURES -g -Wall -Werr -Wextra -O3)

add_executable(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include)
