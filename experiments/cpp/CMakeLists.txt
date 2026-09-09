cmake_minimum_required(VERSION 3.20)

project(aapa_crypto_bench LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(liboqs CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(aapa_crypto_bench
    aapa_crypto_bench.cpp
)

target_compile_options(aapa_crypto_bench PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(aapa_crypto_bench PRIVATE
    OQS::oqs
    OpenSSL::Crypto
)
