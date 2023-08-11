cmake_minimum_required(VERSION 3.20)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_COMPILE_FEATURES -g -Wall -Werr -Wextra -O3)

include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include)

project(blockchain LANGUAGES CXX VERSION 0.0.1)
file(GLOB_RECURSE SOURCES ${CMAKE_SOURCE_DIR}/src/*.cc)
add_executable(${PROJECT_NAME} ${SOURCES})


file(GLOB_RECURSE TESTS ${CMAKE_SOURCE_DIR}/tests/test_*.cc)
foreach(path ${TESTS})
        get_filename_component(name ${path} NAME)
        get_filename_component(test_name ${path} NAME_WE)
        add_executable(${name}.out ${CMAKE_SOURCE_DIR}/tests/${name})
        add_test(NAME ${test_name} COMMAND ${name}.out)
endforeach()
enable_testing()