#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR=$( dirname "${SCRIPT_DIR}" )

# Start a server in the background
python3 "$SCRIPT_DIR/runserver.py" &

testserverpid=$!

# Kill it when the script exits
trap "kill $testserverpid" EXIT

# Give 0.1 seconds to startup
sleep 0.1

# Figure out the IP address
IP_address=$(ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p' | head -1 | strings)

env BURPA_TESTING_IP=$IP_address $SCRIPT_DIR/tests.bats