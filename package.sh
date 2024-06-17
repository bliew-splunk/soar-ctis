#!/usr/bin/env bash
version=$(jq -r ".app_version" ctis.json)
output="build/ctis-$version.tgz"
echo "Output: $output"
tar --exclude=".*" --exclude="build" -C /Users/bliew/dev -czvf "$output" soar-ctis
