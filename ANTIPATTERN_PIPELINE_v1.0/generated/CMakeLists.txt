cmake_minimum_required(VERSION 3.10)
project(UseAfterFreeChecker)

find_package(LLVM REQUIRED COMPONENTS clang)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(UseAfterFreeChecker SHARED src/UseAfterFreeChecker.cpp)

target_link_libraries(UseAfterFreeChecker
  ${LLVM_LIBRARIES}
  ${CLANG_LIBRARIES}
)

target_compile_options(UseAfterFreeChecker PRIVATE
  -DLLVM_EXTERNAL_PROJECT
  -fPIC
  -std=c++17
)

install(TARGETS UseAfterFreeChecker DESTINATION lib)
install(FILES src/UseAfterFreeChecker.cpp DESTINATION include)

