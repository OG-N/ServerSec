#!/usr/bin/env bats

load test_helper

@test "Verify that kernel module cramfs is disabled" {
  run bash -c "modprobe -n -v cramfs | grep 'install /bin/true'"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module freevxfs is disabled" {
  run bash -c "modprobe -n -v freevxfs | grep 'install /bin/true'"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module jffs2 is disabled" {
  run bash -c "modprobe -n -v jffs2 | grep 'install /bin/true'"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module hfs is disabled" {
  run bash -c "modprobe -n -v hfs | grep 'install /bin/true'"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module hfsplus is disabled" {
  run bash -c "modprobe -n -v hfsplus | grep 'install /bin/true'"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module squashfs is disabled" {
  run bash -c "modprobe -n -v squashfs | grep 'install /bin/true'"
  run bash -c "modprobe -c | grep squashfs | grep 'install /bin/true'"
  [ "$?" -eq 0 ] || [ "$status" -eq 0 ]
}

@test "Verify that kernel module udf is disabled" {
  run bash -c "modprobe -n -v udf | grep 'install /bin/true'"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module vfat is disabled" {
  run bash -c "modprobe -n -v vfat | grep 'install /bin/true'"
  run bash -c "modprobe -c | grep vfat | grep 'install /bin/true'"
  [ "$?" -eq 0 ] || [ "$status" -eq 0 ]
}
