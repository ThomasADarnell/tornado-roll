cmake_minimum_required(VERSION 3.18)
project(tornado LANGUAGES CXX C)

set(RAYLIB_VERSION 5.5)
find_package(raylib ${RAYLIB_VERSION} QUIET)
if (NOT raylib_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        raylib
        DOWNLOAD_EXTRACT_TIMESTAMP OFF
        URL https://github.com/raysan5/raylib/archive/refs/tags/${RAYLIB_VERSION}.tar.gz
    )
    FetchContent_GetProperties(raylib)
    if (NOT raylib_POPULATED)
        set(FETCHCONTENT_QUIET NO)
        set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(raylib)
    endif()
endif()

if(WIN32)
    find_package(ENet CONFIG REQUIRED)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ENET REQUIRED libenet)
    include_directories(${ENET_INCLUDE_DIRS})
endif()

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/generated)
set(RESOURCE_FILES
    cat.png
    catb.png
    catr.png
    catw.png
    fish.png
    happycat.png
    reno.png
)
foreach(RESOURCE ${RESOURCE_FILES})
    configure_file(
        ${CMAKE_SOURCE_DIR}/src/${RESOURCE}
        ${CMAKE_BINARY_DIR}/generated/${RESOURCE}
        COPYONLY
    )
endforeach()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(raylib-cpp)

add_executable(tornado src/ray.cpp)
add_executable(coordinator src/coord.cpp)

target_link_libraries(tornado PRIVATE 
    raylib 
    raylib_cpp
    $<IF:$<BOOL:${WIN32}>,enet,${ENET_LIBRARIES}>
)

target_link_libraries(coordinator PRIVATE 
    $<IF:$<BOOL:${WIN32}>,enet,${ENET_LIBRARIES}>
)

target_include_directories(tornado PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(coordinator PRIVATE ${CMAKE_SOURCE_DIR}/include)

if(UNIX AND NOT APPLE)
    target_link_libraries(tornado PRIVATE m)
    target_link_libraries(coordinator PRIVATE m)
endif()
