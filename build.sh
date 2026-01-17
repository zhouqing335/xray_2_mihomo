#!/bin/bash

# Build script for xray2clash

echo "Building xray2clash..."

# Compile the C program
gcc main.c cJSON.c -o xray2clash

# Check if compilation was successful
if [ $? -eq 0 ]; then
    echo "Build successful! Executable: xray2clash"
else
    echo "Build failed!"
    exit 1
fi