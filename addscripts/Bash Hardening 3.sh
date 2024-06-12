#!/bin/bash
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_sshd_set_keepalive='3'


if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*ClientAliveCountMax\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "ClientAliveCountMax $var_sshd_set_keepalive" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

sshd_idle_timeout_value='300'


if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*ClientAliveInterval\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "ClientAliveInterval $sshd_idle_timeout_value" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

mkdir -p /etc/ssh/sshd_config.d
touch /etc/ssh/sshd_config.d/00-complianceascode-hardening.conf

LC_ALL=C sed -i "/^\s*PermitRootLogin\s\+/Id" "/etc/ssh/sshd_config"
LC_ALL=C sed -i "/^\s*PermitRootLogin\s\+/Id" "/etc/ssh/sshd_config.d"/*.conf
if [ -e "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*PermitRootLogin\s\+/Id" "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
else
    touch "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"

cp "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf" "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf.bak"
# Insert at the beginning of the file
printf '%s\n' "PermitRootLogin no" > "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
cat "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf.bak" >> "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

mkdir -p /etc/ssh/sshd_config.d
touch /etc/ssh/sshd_config.d/00-complianceascode-hardening.conf

LC_ALL=C sed -i "/^\s*AllowTcpForwarding\s\+/Id" "/etc/ssh/sshd_config"
LC_ALL=C sed -i "/^\s*AllowTcpForwarding\s\+/Id" "/etc/ssh/sshd_config.d"/*.conf
if [ -e "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*AllowTcpForwarding\s\+/Id" "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
else
    touch "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"

cp "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf" "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf.bak"
# Insert at the beginning of the file
printf '%s\n' "AllowTcpForwarding no" > "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
cat "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf.bak" >> "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

mkdir -p /etc/ssh/sshd_config.d
touch /etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf

LC_ALL=C sed -i "/^\s*X11Forwarding\s\+/Id" "/etc/ssh/sshd_config"
LC_ALL=C sed -i "/^\s*X11Forwarding\s\+/Id" "/etc/ssh/sshd_config.d"/*.conf
if [ -e "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*X11Forwarding\s\+/Id" "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"
else
    touch "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"

cp "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf" "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf.bak"
# Insert at the beginning of the file
printf '%s\n' "X11Forwarding no" > "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"
cat "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf.bak" >> "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

mkdir -p /etc/ssh/sshd_config.d
touch /etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf

LC_ALL=C sed -i "/^\s*PermitUserEnvironment\s\+/Id" "/etc/ssh/sshd_config"
LC_ALL=C sed -i "/^\s*PermitUserEnvironment\s\+/Id" "/etc/ssh/sshd_config.d"/*.conf
if [ -e "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*PermitUserEnvironment\s\+/Id" "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"
else
    touch "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"

cp "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf" "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf.bak"
# Insert at the beginning of the file
printf '%s\n' "PermitUserEnvironment no" > "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"
cat "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf.bak" >> "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

mkdir -p /etc/ssh/sshd_config.d
touch /etc/ssh/sshd_config.d/00-complianceascode-hardening.conf

LC_ALL=C sed -i "/^\s*Banner\s\+/Id" "/etc/ssh/sshd_config"
LC_ALL=C sed -i "/^\s*Banner\s\+/Id" "/etc/ssh/sshd_config.d"/*.conf
if [ -e "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*Banner\s\+/Id" "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
else
    touch "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"

cp "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf" "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf.bak"
# Insert at the beginning of the file
printf '%s\n' "Banner /etc/issue.net" > "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
cat "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf.bak" >> "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_sshd_set_login_grace_time='60'


if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*LoginGraceTime\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "LoginGraceTime $var_sshd_set_login_grace_time" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

sshd_max_auth_tries_value='4'


if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*MaxAuthTries\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "MaxAuthTries $sshd_max_auth_tries_value" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_sshd_max_sessions='10'


if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*MaxSessions\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "MaxSessions $var_sshd_max_sessions" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_sshd_set_maxstartups='10:30:60'


if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*MaxStartups\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "MaxStartups $var_sshd_set_maxstartups" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*Ciphers\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

sshd_strong_kex='curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256'


if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*KexAlgorithms\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "KexAlgorithms $sshd_strong_kex" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

sshd_strong_macs='hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256'


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^MACs")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "$sshd_strong_macs"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^MACs\\>" "/etc/ssh/sshd_config"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^MACs\\>.*/$escaped_formatted_output/gi" "/etc/ssh/sshd_config"
else
    if [[ -s "/etc/ssh/sshd_config" ]] && [[ -n "$(tail -c 1 -- "/etc/ssh/sshd_config" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/ssh/sshd_config"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/ssh/sshd_config"
fi

var_accounts_minimum_age_login_defs='1'


while IFS= read -r i; do
    
    chage -m $var_accounts_minimum_age_login_defs $i

done <   <(awk -v var="$var_accounts_minimum_age_login_defs" -F: '(/^[^:]+:[^!*]/ && ($4 < var || $4 == "")) {print $1}' /etc/shadow)
# Remediation is applicable only in certain platforms
if ( [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'nftables' 2>/dev/null | grep -q installed ); then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'nftables.service'
"$SYSTEMCTL_EXEC" start 'nftables.service'
"$SYSTEMCTL_EXEC" enable 'nftables.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# CAUTION: This remediation script will remove ufw
#	   from the system, and may remove any packages
#	   that depend on ufw. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

DEBIAN_FRONTEND=noninteractive apt-get remove -y "ufw"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install cramfs" /etc/modprobe.d/cramfs.conf ; then
	
	sed -i 's#^install cramfs.*#install cramfs /bin/true#g' /etc/modprobe.d/cramfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/cramfs.conf
	echo "install cramfs /bin/false" >> /etc/modprobe.d/cramfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist cramfs$" /etc/modprobe.d/cramfs.conf ; then
	echo "blacklist cramfs" >> /etc/modprobe.d/cramfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install squashfs" /etc/modprobe.d/squashfs.conf ; then
	
	sed -i 's#^install squashfs.*#install squashfs /bin/true#g' /etc/modprobe.d/squashfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/squashfs.conf
	echo "install squashfs /bin/false" >> /etc/modprobe.d/squashfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist squashfs$" /etc/modprobe.d/squashfs.conf ; then
	echo "blacklist squashfs" >> /etc/modprobe.d/squashfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install udf" /etc/modprobe.d/udf.conf ; then
	
	sed -i 's#^install udf.*#install udf /bin/true#g' /etc/modprobe.d/udf.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/udf.conf
	echo "install udf /bin/false" >> /etc/modprobe.d/udf.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist udf$" /etc/modprobe.d/udf.conf ; then
	echo "blacklist udf" >> /etc/modprobe.d/udf.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install usb-storage" /etc/modprobe.d/usb-storage.conf ; then
	
	sed -i 's#^install usb-storage.*#install usb-storage /bin/true#g' /etc/modprobe.d/usb-storage.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/usb-storage.conf
	echo "install usb-storage /bin/false" >> /etc/modprobe.d/usb-storage.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist usb-storage$" /etc/modprobe.d/usb-storage.conf ; then
	echo "blacklist usb-storage" >> /etc/modprobe.d/usb-storage.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "aide"

AIDE_CONFIG=/etc/aide/aide.conf
DEFAULT_DB_PATH=/var/lib/aide/aide.db

# Fix db path in the config file, if necessary
if ! grep -q '^database=file:' ${AIDE_CONFIG}; then
    # replace_or_append gets confused by 'database=file' as a key, so should not be used.
    #replace_or_append "${AIDE_CONFIG}" '^database=file' "${DEFAULT_DB_PATH}" '@CCENUM@' '%s:%s'
    echo "database=file:${DEFAULT_DB_PATH}" >> ${AIDE_CONFIG}
fi

# Fix db out path in the config file, if necessary
if ! grep -q '^database_out=file:' ${AIDE_CONFIG}; then
    echo "database_out=file:${DEFAULT_DB_PATH}.new" >> ${AIDE_CONFIG}
fi

/usr/sbin/aideinit -y -f

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "systemd-timesyncd"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { dpkg-query --show --showformat='${db:Status-Status}\n' 'ntp' 2>/dev/null | grep -q installed; }; then

if grep -q 'OPTIONS=.*' /etc/sysconfig/ntpd; then
	# trying to solve cases where the parameter after OPTIONS
	#may or may not be enclosed in quotes
	sed -i -E 's/^([\s]*OPTIONS=["]?[^"]*)("?)/\1 -u ntp:ntp\2/' /etc/sysconfig/ntpd
else
	echo 'OPTIONS="-u ntp:ntp"' >> /etc/sysconfig/ntpd
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install usb-storage" /etc/modprobe.d/usb-storage.conf ; then
	
	sed -i 's#^install usb-storage.*#install usb-storage /bin/true#g' /etc/modprobe.d/usb-storage.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/usb-storage.conf
	echo "install usb-storage /bin/false" >> /etc/modprobe.d/usb-storage.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist usb-storage$" /etc/modprobe.d/usb-storage.conf ; then
	echo "blacklist usb-storage" >> /etc/modprobe.d/usb-storage.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
FILTER_NODEV=$(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,)
PARTITIONS=$(findmnt -n -l -k -it $FILTER_NODEV | awk '{ print $1 }')
for PARTITION in $PARTITIONS; do
  find "${PARTITION}" -xdev -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null
done

# Ensure /tmp is also fixed whem tmpfs is used.
if grep "^tmpfs /tmp" /proc/mounts; then
  find /tmp -xdev -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install cramfs" /etc/modprobe.d/cramfs.conf ; then
	
	sed -i 's#^install cramfs.*#install cramfs /bin/true#g' /etc/modprobe.d/cramfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/cramfs.conf
	echo "install cramfs /bin/false" >> /etc/modprobe.d/cramfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist cramfs$" /etc/modprobe.d/cramfs.conf ; then
	echo "blacklist cramfs" >> /etc/modprobe.d/cramfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install squashfs" /etc/modprobe.d/squashfs.conf ; then
	
	sed -i 's#^install squashfs.*#install squashfs /bin/true#g' /etc/modprobe.d/squashfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/squashfs.conf
	echo "install squashfs /bin/false" >> /etc/modprobe.d/squashfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist squashfs$" /etc/modprobe.d/squashfs.conf ; then
	echo "blacklist squashfs" >> /etc/modprobe.d/squashfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { dpkg-query --show --showformat='${db:Status-Status}\n' 'grub2-common' 2>/dev/null | grep -q installed; }; then

# Correct the form of default kernel command line in GRUB
if grep -q '^\s*GRUB_CMDLINE_LINUX=.*audit_backlog_limit=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an audit_backlog_limit= arg already exists
       sed -i "s/\(^\s*GRUB_CMDLINE_LINUX=\".*\)audit_backlog_limit=[^[:space:]]\+\(.*\"\)/\1audit_backlog_limit=8192\2/"  '/etc/default/grub'
# Add to already existing GRUB_CMDLINE_LINUX parameters
elif grep -q '^\s*GRUB_CMDLINE_LINUX='  '/etc/default/grub' ; then
       # no audit_backlog_limit=arg is present, append it
       sed -i "s/\(^\s*GRUB_CMDLINE_LINUX=\".*\)\"/\1 audit_backlog_limit=8192\"/"  '/etc/default/grub'
# Add GRUB_CMDLINE_LINUX parameters line
