#!/bin/bash

# Fetch the list of Ubuntu LTS versions
versions=$(curl -s https://changelogs.ubuntu.com/meta-release-lts | grep -Po '(?<=Version: )[^ ]*' | sort -Vr)

# Prepare the current year
current_year=$(date +"%Y")

# Prepare the JSON array for the matrix strategy
supported_versions=()
for version in $versions; do
  release_year=$(echo $version | grep -oP '^\d{2}' | sed 's/^/20/')
  if (( current_year - release_year < 5 )); then
    supported_versions+=("$version")
  fi
done

matrix_json=$(printf '%s\n' "${supported_versions[@]}" | jq -R . | jq -s .)

echo "Supported Ubuntu LTS versions: $matrix_json"
echo "::set-output name=supported-ubuntu-lts::$matrix_json"
