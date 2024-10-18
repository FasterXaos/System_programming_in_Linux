#!/bin/bash

export LANG=en_US.UTF-8

BUILD_TYPE=Ninja
BUILD_SUFFIX=ninja

BUILD_FOLDER="build_${BUILD_SUFFIX}"
CONFIG_FILE="backup_config.ini"
SERVICE_FILE="backup_daemon.service"

if [ ! -d "$BUILD_FOLDER" ]; then
    mkdir $BUILD_FOLDER
fi

cd $BUILD_FOLDER

cp "../$CONFIG_FILE" .
cp "../$SERVICE_FILE" .

cmake -G "$BUILD_TYPE" ..

cmake --build .
