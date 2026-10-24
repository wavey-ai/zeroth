#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
output="${1:?usage: deploy/aws/package.sh OUTPUT.zip}"
mkdir -p "$(dirname "$output")" build/zeroth-authorizer-bin
docker buildx build --platform linux/arm64 --provenance=false \
  --output type=local,dest=build/zeroth-authorizer-bin \
  -f deploy/aws/Dockerfile .
zip -j -q "$output" build/zeroth-authorizer-bin/bootstrap
printf '%s\n' "$output"
