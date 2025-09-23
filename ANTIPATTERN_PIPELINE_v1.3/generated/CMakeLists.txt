cmake_minimum_required(VERSION 3.10)
project(BufferOverflowChecker)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(BufferOverflowChecker SHARED
    BufferOverflowChecker.cpp
)

target_include_directories(BufferOverflowChecker
    PUBLIC
        ${LLVM_INCLUDE_DIRS}
        ${Clang_INCLUDE_DIRS}
)

target_link_libraries(BufferOverflowChecker
    PRIVATE
        clangFrontend
        clangAST
        clangAnalysis
        clangBasic
        clangLex
        clangParse
        clangSema
        LLVMSupport
        LLVMCore
        LLVMIRReader
        LLVMAnalysis
        LLVMTransformsUtils
        LLVMInstCombine
        LLVMPasses
        LLVMTarget
        LLVMCodeGen
        LLVMBitWriter
        LLVMBitReader
)

target_compile_features(BufferOverflowChecker PRIVATE cxx_std_17)

# Add compiler flags
target_compile_options(BufferOverflowChecker
    PRIVATE
        -Wall
        -Wextra
        -Werror
        -fPIC
)

# Install the library
install(TARGETS BufferOverflowChecker
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    COMPONENT dev
)

install(FILES BufferOverflowChecker.h
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include/BufferOverflowChecker
    COMPONENT dev
)