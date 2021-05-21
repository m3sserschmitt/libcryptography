cmake_minimum_required(VERSION 3.0.0)
project(libcryptography VERSION 0.1.0)

include(CTest)
enable_testing()

add_library(cryptography SHARED src/aes.cc src/rsa.cc src/base64.cc src/sha.cc)
target_include_directories(cryptography PUBLIC include)

target_link_libraries(cryptography crypto)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
