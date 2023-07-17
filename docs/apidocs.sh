#!/bin/bash
# This shell script builds the apidocs for burpa

# Resolve current directory path. Code from https://stackoverflow.com/questions/59895/how-to-get-the-source-directory-of-a-bash-script-from-within-the-script-itself/246128#246128
# Resolve $SOURCE until the file is no longer a symlink
# If $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"; SOURCE="$(readlink "$SOURCE")"; [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"; done
DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"

# Stop if errors
set -euo pipefail
IFS=$'\n\t,'

# Figure the project version
project_version="$(python3 setup.py -V)"

# Figure commit ref
git_sha="$(git rev-parse HEAD)"
if ! git describe --exact-match --tags > /dev/null 2>&1 ; then
    is_tag=false
else
    git_sha="$(git describe --exact-match --tags)"
    is_tag=true
fi

# Init output folder
docs_folder="$( dirname "$DIR" )/apidocs/"
rm -rf "${docs_folder}"
mkdir -p "${docs_folder}"

# Run pydoctor build
pydoctor \
    --project-name="burpa: Burp Automator ${project_version}" \
    --project-url="https://github.com/tristanlatr/burpa" \
    --html-viewsource-base="https://github.com/tristanlatr/burpa/tree/${git_sha}" \
    --make-html \
    --quiet \
    --project-base-dir="$( dirname "$DIR" )"\
    --docformat=numpy \
    --pyval-repr-maxlines=0 \
    --intersphinx=https://docs.python.org/3/objects.inv \
    --html-output="${docs_folder}" \
    ./burpa

echo "API docs generated in ${docs_folder}"