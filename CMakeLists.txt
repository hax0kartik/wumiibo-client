cmake_minimum_required(VERSION 3.1)

set(PROJECT Wumiibo)
project(${PROJECT})
set(CMAKE_CXX_STANDARD 17)

add_compile_options(-Wall -Wextra)

set(SOURCES
    source/main.cpp
    source/communicator.cpp
    source/AmiiboUtil.cpp
)

set(HEADERS
    source/amiibo_map.h
    source/amiibo_structs.h
    source/communicator.h
    source/AmiiboUtil.h
    source/cpu_guess.h
    source/bswap.h
)

add_executable(${PROJECT} ${SOURCES} ${HEADERS})
target_link_libraries(${PROJECT} nana jpeg png z gdi32 comdlg32 ws2_32 -static)