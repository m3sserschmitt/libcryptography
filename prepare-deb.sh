#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

PACKAGE_NAME=libcryptography5

LIB_VERSION=5.0.1
LIB_MAJOR_VERSION=5

DEB=/deb
LIB_INSTALL_DIR=/usr/lib
HEADER_INSTALL_DIR=/usr/include/cryptography

rm -v .$DEB/$PACKAGE_NAME$LIB_INSTALL_DIR/*
rm -v .$DEB/$PACKAGE_NAME-dev$HEADER_INSTALL_DIR/*
rm -v .$DEB/$PACKAGE_NAME-dev$LIB_INSTALL_DIR/*

cp -v ./build/libcryptography.so.$LIB_VERSION .$DEB/$PACKAGE_NAME$LIB_INSTALL_DIR
cp -v ./build/libcryptography.so.$LIB_VERSION ./build/$PACKAGE_NAME.a .$DEB/$PACKAGE_NAME-dev$LIB_INSTALL_DIR
cp -v ./include/* .$DEB/$PACKAGE_NAME-dev$HEADER_INSTALL_DIR

cd $SCRIPTPATH$DEB/$PACKAGE_NAME$LIB_INSTALL_DIR

ln -s -v libcryptography.so.$LIB_VERSION libcryptography.so.$LIB_MAJOR_VERSION
ln -s -v libcryptography.so.$LIB_MAJOR_VERSION libcryptography.so

cd $SCRIPTPATH$DEB/$PACKAGE_NAME-dev$LIB_INSTALL_DIR

ln -s -v libcryptography.so.$LIB_VERSION libcryptography.so.$LIB_MAJOR_VERSION
ln -s -v libcryptography.so.$LIB_MAJOR_VERSION libcryptography.so

cd $SCRIPTPATH$DEB

dpkg-deb --build $PACKAGE_NAME
dpkg-deb --build $PACKAGE_NAME-dev
