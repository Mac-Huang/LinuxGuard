# LinuxGuard Static Checkers CMakeLists.txt

cmake_minimum_required(VERSION 3.13.4)
project(LinuxGuardCheckers)

find_package(Clang REQUIRED)

# Add checker sources
set(CHECKER_SOURCES
  checkers/checker_ap_fallback_000.cpp
  checkers/checker_ap_fallback_000.cpp
  checkers/checker_ap_fallback_000.cpp
)

# Create checker library
add_library(LinuxGuardCheckers SHARED ${CHECKER_SOURCES})

target_link_libraries(LinuxGuardCheckers
  clangStaticAnalyzerCore
  clangStaticAnalyzerCheckers
  clangAST
  clangBasic
)

target_include_directories(LinuxGuardCheckers PRIVATE
  ${CLANG_INCLUDE_DIRS}
)
