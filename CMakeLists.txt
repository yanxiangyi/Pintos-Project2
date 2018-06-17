cmake_minimum_required(VERSION 3.8)
project(Project2)

include_directories(${PROJECT_SOURCE_DIR} "lib/" "lib/kernel/" "lib/user/" "devices/" "examples/" "filesys/" "threads/" "userprog/" "utils/")
file(GLOB SOURCES "*/*.c" "*/*/*.c" "*/*/*/*.c" "*/*.h" "*/*/*.h" main.cpp)

set(CMAKE_CXX_STANDARD 11)

add_executable(pintos main.cpp ${SOURCES})