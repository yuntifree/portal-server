#!/bin/bash



for dir in ../proto/*/; do
    dir=${dir%/}
    echo $dir
    cd $dir
    protoc --go_out=plugins=micro:. *.proto
    cd -
done
