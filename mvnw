#!/bin/sh

set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
wrapper_dir="$project_dir/.mvn/wrapper"
maven_version=3.9.11
maven_home="$wrapper_dir/apache-maven-$maven_version"
archive="$wrapper_dir/apache-maven-$maven_version-bin.zip"

if [ ! -x "$maven_home/bin/mvn" ]; then
  mkdir -p "$wrapper_dir"
  if [ ! -f "$archive" ]; then
    curl -fsSL "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/$maven_version/apache-maven-$maven_version-bin.zip" -o "$archive"
  fi
  if command -v unzip >/dev/null 2>&1; then
    unzip -q -o "$archive" -d "$wrapper_dir"
  else
    echo "unzip is required to install Maven $maven_version" >&2
    exit 1
  fi
fi

exec "$maven_home/bin/mvn" "$@"
