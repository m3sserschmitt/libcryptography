cmake_minimum_required(VERSION 3.0.0)

project(libcryptography VERSION 7.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(cryptography SHARED 
./src/aes.cc 
./src/aes_auth.cc
./src/base64.cc 
./src/rsa.cc 
./src/random.cc 
./src/sha.cc
./src/hex.cc
)

set_target_properties(cryptography PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 7)

add_library(cryptography7 STATIC 
./src/aes.cc 
./src/aes_auth.cc
./src/base64.cc 
./src/rsa.cc 
./src/random.cc 
./src/sha.cc
./src/hex.cc
)

target_link_libraries(cryptography crypto)
target_link_libraries(cryptography7 crypto)
