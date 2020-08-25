cmake_minimum_required(VERSION 3.1)

set(PROJECT Wumiibo)
project(${PROJECT})
set(CMAKE_CXX_STANDARD 17)
add_compile_options(-Wall -Wextra)


set(NO_GUI "OFF" CACHE BOOL
"Set to ON to build the non gui version of Wumiibo-Client")

if(NO_GUI)
    set(SOURCES
        source/main_non_gui.cpp
        source/communicator.cpp
        source/AmiiboUtil.cpp
    )

else(NO_GUI)
    set(SOURCES
        source/main.cpp
        source/communicator.cpp
        source/AmiiboUtil.cpp
    )
endif(NO_GUI)

set(HEADERS
    source/amiibo_map.h
    source/amiibo_structs.h
    source/communicator.h
    source/AmiiboUtil.h
    source/cpu_guess.h
    source/bswap.h
)

add_executable(${PROJECT} ${SOURCES} ${HEADERS})
if(NO_GUI)
    target_link_libraries(${PROJECT} ws2_32 -static)
else(NO_GUI)
    target_link_libraries(${PROJECT} nana jpeg png z gdi32 comdlg32 ws2_32 -static)
endif(NO_GUI)