cmake_minimum_required(VERSION 3.14)
project(TDEvuris VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCES
    src/main.cpp
    src/boot_scanner.cpp
    src/hasher.cpp
    src/heuristics.cpp
    src/json.cpp
    src/memory_scanner.cpp
    src/network_scanner.cpp
    src/registry_scanner.cpp
    src/scanner.cpp
    src/shredder.cpp
    src/signatures.cpp
    src/updater.cpp
    src/watcher.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE src)

target_link_libraries(${PROJECT_NAME} PRIVATE bcrypt comctl32 shell32 wintrust iphlpapi ws2_32 psapi wininet)
