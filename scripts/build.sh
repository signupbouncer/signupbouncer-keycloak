#!/usr/bin/env bash
# Builds and tests the jar with Maven in a container, for machines without Java:
#
#   bash scripts/build.sh            # mvn -q verify: unit tests, then target/keycloak-signupbouncer-<version>.jar
#   bash scripts/build.sh -DskipTests package
#
# Uses podman, or docker when podman is missing. Maven's downloads are cached in $M2_CACHE
# (default ~/.cache/keycloak-signupbouncer-m2). With Java 17+ and Maven installed, run `mvn verify` instead.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
image="${MAVEN_IMAGE:-docker.io/library/maven:3.9-eclipse-temurin-21}"
cache="${M2_CACHE:-$HOME/.cache/keycloak-signupbouncer-m2}"
engine="$(command -v podman || command -v docker)"
mkdir -p "$cache"
args=("$@")
if [ ${#args[@]} -eq 0 ]; then args=(-q verify); fi

"$engine" run --rm \
  -v "$here:/build:Z" \
  -v "$cache:/root/.m2:Z" \
  -w /build \
  "$image" mvn -B "${args[@]}"
ls -l "$here"/target/keycloak-signupbouncer-*.jar 2>/dev/null || true
