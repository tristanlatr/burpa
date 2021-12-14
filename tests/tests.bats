#!/usr/bin/env bats

# burpa test script

HERE=$BATS_TEST_DIRNAME

TEST_IP=$BURPA_TESTING_IP
echo "Running burpa tests on IP: $TEST_IP"

# Load BATS script libraries
load "$HERE/bats-support/load.bash"
load "$HERE/bats-assert/load.bash"

@test "Test simple scan" {

    run python3 -m burpa scan https://$TEST_IP:4443
    echo $output

    # Test status ok
    assert_success

    assert_output --partial "https://$TEST_IP:4443 has been included to the scope"
    assert_output --partial "Scan status: succeeded"
}

@test "Test simple scan file" {

    run python3 -m burpa scan https://$TEST_IP:4443/index.html
    echo $output

    # Test status ok
    assert_success

    assert_output --partial "https://$TEST_IP:4443/index.html has been included to the scope"
    assert_output --partial "https://$TEST_IP:4443 has been included to the scope"
    assert_output --partial "Scan status: succeeded"
}

@test "Test scan with options" {

}

@test "Test schedule scans" {

}

@test "Test scan from file list" {

}

@test "Test invalid REST API URLs" {

}

@test "Test reports" {

}