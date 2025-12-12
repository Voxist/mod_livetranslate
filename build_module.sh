#!/bin/bash
set -e

# Build mod_livetranslate for FreeSWITCH
# Usage: ./build_module.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="mod_livetranslate_builder"
OUTPUT_DIR="${SCRIPT_DIR}/build_output"

echo "Building mod_livetranslate..."
echo "Working directory: ${SCRIPT_DIR}"

# Build the container (use --platform for ARM Macs)
PLATFORM_FLAG=""
if [[ "$(uname -m)" == "arm64" ]]; then
    PLATFORM_FLAG="--platform linux/amd64"
    echo "Detected ARM architecture, building for linux/amd64"
fi

docker build ${PLATFORM_FLAG} \
    -t "${IMAGE_NAME}" \
    "${SCRIPT_DIR}"

# Extract the compiled module
mkdir -p "${OUTPUT_DIR}"
echo "Extracting mod_livetranslate.so to ${OUTPUT_DIR}..."

CONTAINER_ID=$(docker create "${IMAGE_NAME}")
docker cp "${CONTAINER_ID}:/mod_livetranslate.so" "${OUTPUT_DIR}/"
docker rm "${CONTAINER_ID}"

echo ""
echo "Build successful!"
echo "Module available at: ${OUTPUT_DIR}/mod_livetranslate.so"
echo ""
echo "To install on FreeSWITCH:"
echo "  cp ${OUTPUT_DIR}/mod_livetranslate.so /usr/lib/freeswitch/mod/"
echo "  fs_cli -x 'reload mod_livetranslate'"
