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
)

target_link_libraries(cryptography crypto)
set_target_properties(cryptography PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 7)

add_library(cryptography6 STATIC 
./src/aes.cc 
./src/aes_auth.cc
./src/base64.cc 
./src/rsa.cc 
./src/random.cc 
./src/sha.cc
)

target_link_libraries(cryptography6 crypto)

add_executable(libcryptography_tests ./tests/main.cc)
target_link_libraries(libcryptography_tests cryptography6)
