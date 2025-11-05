cmake_minimum_required(VERSION 3.16)
project(pki487 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Allow vcpkg toolchain if provided
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND EXISTS "${CMAKE_SOURCE_DIR}/vcpkg.json")
  message(STATUS "Using vcpkg manifest mode")
endif()

find_package(OpenSSL REQUIRED)

add_library(pki487_lib
  src/crypto.cpp
  src/io.cpp
  src/cert487.cpp
  src/crl487.cpp
  src/util.cpp
)

target_include_directories(pki487_lib PUBLIC include)

target_link_libraries(pki487_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)

add_executable(pki487 src/main.cpp)

target_link_libraries(pki487 PRIVATE pki487_lib)

# Install rule (optional)
install(TARGETS pki487 RUNTIME DESTINATION bin)
