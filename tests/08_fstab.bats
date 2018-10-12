#!/usr/bin/env bats

load test_helper

@test "Ensure a floppy is not present in /etc/fstab" {
  run bash -c "grep floppy /etc/fstab"
  [ "$status" -eq 1 ]
}

@test "Ensure a floppy is not mounted" {
  run bash -c "grep floppy /proc/mounts"
  [ "$status" -eq 1 ]
}

@test "Ensure /tmp is not present in /etc/fstab" {
  run bash -c "grep -e '[[:space:]]/tmp[[:space:]]' /etc/fstab"
  [ "$status" -eq 1 ]
}

@test "Ensure /var/tmp is not present in /etc/fstab" {
  run bash -c "grep -e '[[:space:]]/var/tmp[[:space:]]' /etc/fstab"
  [ "$status" -eq 1 ]
}

@test "Verify that /tmp is mounted with nodev" {
  tmpMount=$(fragmentPath tmp.mount)
  run bash -c "grep '^Options=.*nodev.*' $tmpMount"
  [ "$status" -eq 0 ]
}

@test "Verify that /tmp is mounted with nosuid" {
  tmpMount=$(fragmentPath tmp.mount)
  run bash -c "grep '^Options=.*nosuid.*' $tmpMount"
  [ "$status" -eq 0 ]
}

@test "Verify that /tmp is mounted with noexec" {
  tmpMount=$(fragmentPath tmp.mount)
  run bash -c "grep '^Options=.*noexec.*' $tmpMount"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/tmp is mounted with nodev" {
  varTmpMount=$(fragmentPath var-tmp.mount)
  run bash -c "grep '^Options=.*nodev.*' $varTmpMount"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/tmp is mounted with nosuid" {
  varTmpMount=$(fragmentPath var-tmp.mount)
  run bash -c "grep '^Options=.*nosuid.*' $varTmpMount"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/tmp is mounted with noexec" {
  varTmpMount=$(fragmentPath var-tmp.mount)
  run bash -c "grep '^Options=.*noexec.*' $varTmpMount"
  [ "$status" -eq 0 ]
}

@test "Verify that /home is a separate partition" {
  run bash -c "grep '[[:space:]]/home[[:space:]]' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /home is mounted with nodev" {
  run bash -c "grep '[[:space:]]/home[[:space:]].*nodev.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /home is mounted with nosuid" {
  run bash -c "grep '[[:space:]]/home[[:space:]].*nosuid.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/log/audit is a separate partition" {
  run bash -c "grep '[[:space:]]/var/log/audit[[:space:]]' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/log is a separate partition" {
  run bash -c "grep '[[:space:]]/var/log[[:space:]]' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /proc is mounted with nodev" {
  run bash -c "grep '[[:space:]]/proc[[:space:]].*nodev.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /proc is mounted with nosuid" {
  run bash -c "grep '[[:space:]]/proc[[:space:]].*nosuid.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /proc is mounted with noexec" {
  run bash -c "grep '[[:space:]]/proc[[:space:]].*noexec.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /dev/shm is mounted with nodev" {
  run bash -c "grep '[[:space:]]/dev/shm[[:space:]].*nodev.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /dev/shm is mounted with nosuid" {
  run bash -c "grep '[[:space:]]/dev/shm[[:space:]].*nosuid.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /run/shm is mounted with nodev" {
  run bash -c "grep '[[:space:]]/run/shm[[:space:]].*nodev.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /run/shm is mounted with nosuid" {
  run bash -c "grep '[[:space:]]/run/shm[[:space:]].*nosuid.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /run/shm is mounted with noexec" {
  run bash -c "grep '[[:space:]]/run/shm[[:space:]].*noexec.*' /proc/mounts"
  [ "$status" -eq 0 ]
}
