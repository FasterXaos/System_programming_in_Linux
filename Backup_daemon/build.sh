#!/bin/bash
#/opt/backup_daemon

export LANG=en_US.UTF-8

BUILD_TYPE=Ninja
BUILD_SUFFIX=ninja

BUILD_FOLDER="build_${BUILD_SUFFIX}"
CONFIG_FILE="backup_config.ini"

if [ ! -d "$BUILD_FOLDER" ]; then
    mkdir $BUILD_FOLDER
fi

cd $BUILD_FOLDER

cmake -G "$BUILD_TYPE" ..

cmake --build .

if [ -f "../$CONFIG_FILE" ]; then
    cp "../$CONFIG_FILE" .
    echo "$CONFIG_FILE скопирован в папку сборки."
else
    echo "$CONFIG_FILE не найден!"
fi
