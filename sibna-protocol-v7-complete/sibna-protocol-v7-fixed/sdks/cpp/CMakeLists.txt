cmake_minimum_required(VERSION 3.15)
project(sibna VERSION 7.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find threads library
find_package(Threads REQUIRED)

# Sibna library
add_library(sibna STATIC
    src/sibna_impl.cpp
)

target_include_directories(sibna PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

target_link_libraries(sibna
    Threads::Threads
)

# Link with Rust FFI library if available
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release/libsibna.a")
    target_link_libraries(sibna
        "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release/libsibna.a"
    )
endif()

# Example executable
add_executable(sibna_example
    example/main.cpp
)

target_link_libraries(sibna_example sibna)

# Tests
enable_testing()

add_executable(sibna_test
    test/test.cpp
)

target_link_libraries(sibna_test sibna)

add_test(NAME SibnaTest COMMAND sibna_test)

# Installation
install(TARGETS sibna
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES include/sibna.hpp
    DESTINATION include
)
