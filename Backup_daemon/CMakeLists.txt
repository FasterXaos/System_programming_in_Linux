cmake_minimum_required(VERSION 3.10)

project(BackupDaemon)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)


set(SOURCES
    main.cpp
)

add_executable(backup_daemon ${SOURCES})

set(CMAKE_BUILD_TYPE Release)


