#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

rm -rf build
mkdir -p build
cp src/fabric.mod.json build/

javac --release 8 -d build src/dev/dexon/examplemod/ExampleMod.java

jar cfM examplemod.jar -C build fabric.mod.json -C build dev

python3 ../bypass.py examplemod.jar -o examplemod-cloaked.jar
