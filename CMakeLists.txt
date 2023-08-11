cmake_minimum_required(VERSION 3.20)

set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g")

include_directories(PUBLIC 
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/lib)

find_package(OpenSSL REQUIRED)
link_libraries(OpenSSL::SSL OpenSSL::Crypto)

project(blockchain LANGUAGES CXX VERSION 0.0.1)
file(GLOB_RECURSE SOURCES ${CMAKE_SOURCE_DIR}/src/*.cc)
add_library(${PROJECT_NAME} SHARED ${SOURCES})

file(GLOB_RECURSE TESTS ${CMAKE_SOURCE_DIR}/tests/test_*.cc)
foreach(path ${TESTS})
        get_filename_component(name ${path} NAME)
        add_executable(${name}.out ${path})
        target_link_libraries(${name}.out PRIVATE ${PROJECT_NAME})
        add_test(NAME ${name} COMMAND ${name}.out)
endforeach()
enable_testing()