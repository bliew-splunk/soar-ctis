#!/usr/bin/env bash
set -xe
version=$(jq -r ".app_version" ctis.json)
output="build/ctis-$version.tgz"
echo "Output: $output"
tar --exclude=".*" --exclude="build" -C ../ -czvf "$output" soar-ctis
