#!/usr/bin/env bats

load test_helper

@test "Ensure OpenSSH ssh_host_dsa_key is not used" {
  run sshdConfig ssh_host_dsa_key
  [ "$status" -eq 1 ]
}

@test "Verify OpenSSH UsePrivilegeSeparation (Deprecated)" {
  run sshdConfig UsePrivilegeSeparation
  [ "$status" -eq 1 ]
}

@test "Verify OpenSSH Protocol (Deprecated)" {
  run sshdConfig Protocol
  [ "$status" -eq 1 ]
}

@test "Verify OpenSSH RhostsRSAAuthentication (Deprecated)" {
  run sshdConfig RhostsRSAAuthentication
  [ "$status" -eq 1 ]
}

@test "Verify OpenSSH port $SSH_PORT" {
  run bash -c "sshd -T | grep -i \"^port $SSH_PORT$\""
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH User and Groups access limits" {
  run bash -c "sshd -T | grep -i -E 'allowgroups|allowusers|denygroups|denyusers'"
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH IgnoreRhosts" {
  run sshdConfig '^IgnoreRhosts yes$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH Compression" {
  run sshdConfig '^Compression no$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH KerberosAuthentication" {
  run sshdConfig '^KerberosAuthentication no$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH StrictModes" {
  run sshdConfig '^StrictModes yes$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH GSSAPIAuthentication" {
  run sshdConfig '^GSSAPIAuthentication no$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH X11Forwarding" {
  run sshdConfig '^X11Forwarding no$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH LoginGraceTime" {
  run sshdConfig '^LoginGraceTime 20$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH PermitRootLogin" {
  run sshdConfig '^PermitRootLogin no$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH KeyRegenerationInterval" {
  run sshdConfig '^KeyRegenerationInterval.*$'
  [ "$status" -eq 1 ]
}

@test "Verify OpenSSH LogLevel" {
  run sshdConfig '^LogLevel VERBOSE$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH banner" {
  run sshdConfig '^Banner /etc/issue.net$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH sftp" {
  run sshdConfig '^Subsystem sftp internal-sftp$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH MaxAuthTries" {
  run sshdConfig '^MaxAuthTries .$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH ClientAliveInterval" {
  run sshdConfig '^ClientAliveInterval 300$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH ClientAliveCountMax" {
  run sshdConfig '^ClientAliveCountMax 0$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH PermitUserEnvironment" {
  run sshdConfig '^PermitUserEnvironment no$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH KexAlgorithms" {
  run sshdConfig '^KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH Ciphers" {
  run sshdConfig '^Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH Macs" {
  run sshdConfig '^Macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH MaxSessions" {
  run sshdConfig '^MaxSessions 3$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH UseDNS" {
  run sshdConfig '^UseDNS no$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH PrintLastLog" {
  run sshdConfig '^PrintLastLog yes$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH IgnoreUserKnownHosts" {
  run sshdConfig '^IgnoreUserKnownHosts yes$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH PermitEmptyPasswords" {
  run sshdConfig '^PermitEmptyPasswords no$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH MaxStartups" {
  run sshdConfig '^MaxStartups 10:30:60$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH HostbasedAuthentication" {
  run sshdConfig '^HostbasedAuthentication no$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH RekeyLimit" {
  run sshdConfig '^RekeyLimit [0-9]{5,9} 3600$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH AllowTcpForwarding" {
  run sshdConfig '^AllowTcpForwarding no$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH AllowAgentForwarding" {
  run sshdConfig '^AllowAgentForwarding no$'
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH TCPKeepAlive" {
  run sshdConfig '^TCPKeepAlive no$'
  [ "$status" -eq 0 ]
}

@test "Verify moduli sizes" {
  run moduliSize
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH Client HashKnownHosts" {
  run bash -c "grep '^\s.*HashKnownHosts yes$' /etc/ssh/ssh_config"
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH Client Ciphers" {
  run bash -c "grep '^\s.*Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr$' /etc/ssh/ssh_config"
  [ "$status" -eq 0 ]
}

@test "Verify OpenSSH Client Macs" {
  run bash -c "grep '^\s.*MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256$' /etc/ssh/ssh_config"
  [ "$status" -eq 0 ]
}
