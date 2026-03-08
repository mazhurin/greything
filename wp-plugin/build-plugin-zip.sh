#!/bin/bash
# Build gt-storage WordPress plugin zip
set -e

cd "$(dirname "$0")"

ZIP_NAME="gt-storage.zip"
rm -f "$ZIP_NAME"

zip -r "$ZIP_NAME" gt-storage/ \
  -x "gt-storage/.DS_Store" \
  -x "gt-storage/**/.DS_Store"

echo "Built: $(pwd)/$ZIP_NAME ($(du -h "$ZIP_NAME" | cut -f1))"
