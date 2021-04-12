#!/bin/bash
# Build CLI documentation file

# Resolve current directory path. Code from https://stackoverflow.com/questions/59895/how-to-get-the-source-directory-of-a-bash-script-from-within-the-script-itself/246128#246128
# Resolve $SOURCE until the file is no longer a symlink
# If $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"; SOURCE="$(readlink "$SOURCE")"; [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"; done
DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"

export BURP_API_URL=localhost
esc=$'\e'
main_help=$(burpa --help 2>&1 | sed "s/$esc\[[0-9;]*m//g" | grep -v "Loading .env file" | fold -s -w 120)
main_burpa_help=$(burpa - --help 2>&1 | sed "s/$esc\[[0-9;]*m//g" | grep -v "Loading .env file" | fold -s -w 120)
scan_help=$(burpa scan --help 2>&1 | sed "s/$esc\[[0-9;]*m//g" | grep -v "Loading .env file" | fold -s -w 120)

mkdir -p $DIR/man/

echo "$main_help" > $DIR/man/burpa.txt
echo "" >> $DIR/man/burpa.txt

echo "----------------------------------------------------" >> $DIR/man/burpa.txt
echo "" >> $DIR/man/burpa.txt

echo "$main_burpa_help" >> $DIR/man/burpa.txt
echo "" >> $DIR/man/burpa.txt

echo "----------------------------------------------------" >> $DIR/man/burpa.txt
echo "" >> $DIR/man/burpa.txt

echo "$scan_help" >> $DIR/man/burpa.txt
echo "" >> $DIR/man/burpa.txt

echo "Manpage generated in $DIR/man/burpa.txt"
