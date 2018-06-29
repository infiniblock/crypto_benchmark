cmake_minimum_required(VERSION 3.10)
project(crypto_selection)
set(CMAKE_CXX_STANDARD 11)


include_directories( ${CMAKE_SOURCE_DIR}/include /home/jinjun/opt/boost/include  /home/jinjun/opt/SandyBridge/libkeccak.a.headers) # Please specify this part
link_directories(/home/jinjun/opt/boost/lib)

find_library(SODIUM libsodium.a)  # Use the static link, instead of dynamic link
find_library(SECP256K1 libsecp256k1.a)
find_library(GMP libgmp.a)
find_library(KECCAK
        NAME keccak
        HINTS /home/jinjun/opt/SandyBridge/)

#add_library(keccak ${keccak_SRC})
#file(GLOB keccak_SRC "keccak/*.c" "keccak/*.h" "keccak/*.inc" "keccak/*.macros")

add_library(display src/display.cpp include/display.hpp)

add_library(crypto_perf src/crypto_perf.cpp src/ed25519_perf.cpp include/crypto_perf.hpp include/ed25519_perf.hpp)
add_library(hash_perf src/hash_perf.cpp include/hash_perf.hpp)
add_executable(crypto_selection main.cpp)

target_link_libraries(crypto_selection crypto_perf display  hash_perf ${KECCAK} ${SODIUM} ${SECP256K1} ${GMP} ed25519
        boost_system boost_thread pthread crypto boost_program_options)

