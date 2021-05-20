cmake_minimum_required(VERSION 3.0.0)
project(libcryptography VERSION 0.1.0)

include(CTest)
enable_testing()

add_library(cryptography SHARED src/aes.cc src/rsa.cc src/base64.cc src/util.cc)
# add_library(cryptography STATIC src/aes.cc src/rsa.cc src/base64.cc)

target_include_directories(cryptography PUBLIC include)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
