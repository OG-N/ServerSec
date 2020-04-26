#!/usr/bin/env bats

load test_helper

@test "Verify PSAD is installed" {
  run bash -c "command -v psad > /dev/null 2>&1"
  [ "$status" -eq 0 ]
}

@test "Verify that PSAD is enabled" {
  run bash -c "systemctl is-enabled psad.service"
  [ "$status" -eq 0 ]
}

@test "Verify if some alias to PSAD email exist" {
  run bash -c "tails /etc/aliases  | grep '^$USER : $MYEMAIL$'"
  [ "$status" -eq 0 ]
}
