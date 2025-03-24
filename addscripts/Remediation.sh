#!/bin/bash
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

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
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "aide"

if grep -i '^.*/usr/sbin/auditctl.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/auditctl.*#/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

if grep -i '^.*/usr/sbin/auditd.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/auditd.*#/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

if grep -i '^.*/usr/sbin/ausearch.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/ausearch.*#/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

if grep -i '^.*/usr/sbin/aureport.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/aureport.*#/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

if grep -i '^.*/usr/sbin/autrace.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/autrace.*#/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

if grep -i '^.*/usr/sbin/augenrules.*$' /etc/aide/aide.conf; then
sed -i "s#.*/usr/sbin/augenrules.*#/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
else
echo "/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
for f in /etc/sudoers /etc/sudoers.d/* ; do
  if [ ! -e "$f" ] ; then
    continue
  fi
  matching_list=$(grep -P '^(?!#).*[\s]+NOPASSWD[\s]*\:.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      # comment out "NOPASSWD" matches to preserve user data
      sed -i "s/^${entry}$/# &/g" $f
    done <<< "$matching_list"

    /usr/sbin/visudo -cf $f &> /dev/null || echo "Fail to validate $f with visudo"
  fi
done

for f in /etc/sudoers /etc/sudoers.d/* ; do
  if [ ! -e "$f" ] ; then
    continue
  fi
  matching_list=$(grep -P '^(?!#).*[\s]+\!authenticate.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      # comment out "!authenticate" matches to preserve user data
      sed -i "s/^${entry}$/# &/g" $f
    done <<< "$matching_list"

    /usr/sbin/visudo -cf $f &> /dev/null || echo "Fail to validate $f with visudo"
  fi
done
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q '^installed'; then

if [ -f /usr/bin/authselect ]; then
    if authselect list-features sssd | grep -q with-pwhistory; then
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi
        authselect enable-feature with-pwhistory

        authselect apply-changes -b
    else
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            # The "local" profile does not contain essential security features required by multiple Benchmarks.
            # If currently used, it is replaced by "sssd", which is the best option in this case.
            if [[ $CURRENT_PROFILE == local ]]; then
                CURRENT_PROFILE="sssd"
            fi
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "cac_pwhistory")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
        
        if ! grep -qP "^\s*password\s+requisite\s+pam_pwhistory.so\s*.*" "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1requisite \2/" "$PAM_FILE_PATH"
            else
                echo "password    requisite    pam_pwhistory.so" >> "$PAM_FILE_PATH"
            fi
        fi
    fi
else

conf_name=cac_pwhistory
conf_path="/usr/share/pam-configs"

if [ ! -f "$conf_path"/"$conf_name" ]; then
    cat << EOF > "$conf_path"/"$conf_name"
Name: pwhistory password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password: requisite pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok
Password-Initial: requisite pam_pwhistory.so remember=24 enforce_for_root try_first_pass
EOF
fi

DEBIAN_FRONTEND=noninteractive pam-auth-update

fi
conf_file=/usr/share/pam-configs/cac_pwhistory
if ! grep -qE 'pam_pwhistory\.so\s+[^#\n]*\benforce_for_root\b' "$conf_file"; then
	sed -i -E '/^Password:/,/^[^[:space:]]/ {
    /pam_pwhistory\.so/ {
        s/$/ enforce_for_root/g
    }
    }' "$conf_file"

    sed -i -E '/^Password-Initial:/,/^[^[:space:]]/ {
    /pam_pwhistory\.so/ {
        s/$/ enforce_for_root/g
    }
    }' "$conf_file"
fi

DEBIAN_FRONTEND=noninteractive pam-auth-update --enable cac_pwhistory

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q '^installed'; then

var_accounts_passwords_pam_faillock_deny='4'


if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
conf_name=cac_faillock

if [ ! -f /usr/share/pam-configs/"$conf_name" ]; then
    cat << EOF > /usr/share/pam-configs/"$conf_name"
Name: Enable pam_faillock to deny access
Default: yes
Conflicts: faillock
Priority: 0
Auth-Type: Primary
Auth:
    [default=die]                   pam_faillock.so authfail
EOF
fi

if [ ! -f /usr/share/pam-configs/"$conf_name"_notify ]; then
    cat << EOF > /usr/share/pam-configs/"$conf_name"_notify
Name: Notify of failed login attempts and reset count upon success
Default: yes
Conflicts: faillock_notify
Priority: 1025
Auth-Type: Primary
Auth:
    requisite                       pam_faillock.so preauth
Account-Type: Primary
Account:
    required                        pam_faillock.so
EOF
fi

DEBIAN_FRONTEND=noninteractive pam-auth-update


fi

AUTH_FILES=("/etc/pam.d/common-auth")
SKIP_FAILLOCK_CHECK=true

FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ] || [ "$SKIP_FAILLOCK_CHECK" = "true" ]; then
    regex="^\s*deny\s*="
    line="deny = $var_accounts_passwords_pam_faillock_deny"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(deny\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_deny"'|g' $FAILLOCK_CONF
    fi
    
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*deny' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
        fi
    done
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q '^installed'; then

var_accounts_passwords_pam_faillock_unlock_time='900'


if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
conf_name=cac_faillock

if [ ! -f /usr/share/pam-configs/"$conf_name" ]; then
    cat << EOF > /usr/share/pam-configs/"$conf_name"
Name: Enable pam_faillock to deny access
Default: yes
Conflicts: faillock
Priority: 0
Auth-Type: Primary
Auth:
    [default=die]                   pam_faillock.so authfail
EOF
fi

if [ ! -f /usr/share/pam-configs/"$conf_name"_notify ]; then
    cat << EOF > /usr/share/pam-configs/"$conf_name"_notify
Name: Notify of failed login attempts and reset count upon success
Default: yes
Conflicts: faillock_notify
Priority: 1025
Auth-Type: Primary
Auth:
    requisite                       pam_faillock.so preauth
Account-Type: Primary
Account:
    required                        pam_faillock.so
EOF
fi

DEBIAN_FRONTEND=noninteractive pam-auth-update


fi

AUTH_FILES=("/etc/pam.d/common-auth")
SKIP_FAILLOCK_CHECK=true

FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ] || [ "$SKIP_FAILLOCK_CHECK" = "true" ]; then
    regex="^\s*root_unlock_time\s*="
    line="root_unlock_time = $var_accounts_passwords_pam_faillock_unlock_time"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(root_unlock_time\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_unlock_time"'|g' $FAILLOCK_CONF
    fi
    
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*root_unlock_time' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ root_unlock_time='"$var_accounts_passwords_pam_faillock_unlock_time"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ root_unlock_time='"$var_accounts_passwords_pam_faillock_unlock_time"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"root_unlock_time"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_unlock_time"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"root_unlock_time"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_unlock_time"'\3/' "$pam_file"
        fi
    done
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q '^installed'; then

var_password_pam_maxsequence='3'







conf_name=cac_pwquality
if [ ! -f /usr/share/pam-configs/"$conf_name" ]; then
    cat << EOF > /usr/share/pam-configs/"$conf_name"
Name: Pwquality password strength checking
Default: yes
Priority: 1025
Conflicts: cracklib, pwquality
Password-Type: Primary
Password:
    requisite                   pam_pwquality.so
EOF
fi

DEBIAN_FRONTEND=noninteractive pam-auth-update


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^maxsequence")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_maxsequence"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^maxsequence\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^maxsequence\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q '^installed'; then

var_password_pam_minclass='4'







conf_name=cac_pwquality
if [ ! -f /usr/share/pam-configs/"$conf_name" ]; then
    cat << EOF > /usr/share/pam-configs/"$conf_name"
Name: Pwquality password strength checking
Default: yes
Priority: 1025
Conflicts: cracklib, pwquality
Password-Type: Primary
Password:
    requisite                   pam_pwquality.so
EOF
fi

DEBIAN_FRONTEND=noninteractive pam-auth-update


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minclass")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minclass"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^minclass\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^minclass\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
ar_accounts_maximum_age_login_defs='365'


while IFS= read -r i; do
    
    chage -M $var_accounts_maximum_age_login_defs $i

done <   <(awk -v var="$var_accounts_maximum_age_login_defs" -F: '(/^[^:]+:[^!*]/ && ($5 > var || $5 == "")) {print $1}' /etc/shadow)
var_accounts_minimum_age_login_defs='1'


while IFS= read -r i; do
    
    chage -m $var_accounts_minimum_age_login_defs $i

done <   <(awk -v var="$var_accounts_minimum_age_login_defs" -F: '(/^[^:]+:[^!*]/ && ($4 < var || $4 == "")) {print $1}' /etc/shadow)
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q '^installed'; then

var_pam_wheel_group_for_su='sugroup'


if ! grep -q "^${var_pam_wheel_group_for_su}:[^:]*:[^:]*:[^:]*" /etc/group; then
    groupadd ${var_pam_wheel_group_for_su}
fi

# group must be empty
gpasswd -M '' ${var_pam_wheel_group_for_su}

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q '^installed'; then

var_pam_wheel_group_for_su='sugroup'


PAM_CONF=/etc/pam.d/su

pamstr=$(grep -P '^auth\s+required\s+pam_wheel\.so\s+(?=[^#]*\buse_uid\b)(?=[^#]*\bgroup=)' ${PAM_CONF})
if [ -z "$pamstr" ]; then
    sed -Ei '/^auth\b.*\brequired\b.*\bpam_wheel\.so/d' ${PAM_CONF} # remove any remaining uncommented pam_wheel.so line
    sed -Ei "/^auth\s+sufficient\s+pam_rootok\.so.*$/a auth             required        pam_wheel.so use_uid group=${var_pam_wheel_group_for_su}" ${PAM_CONF}
else
    group_val=$(echo -n "$pamstr" | grep -Eo '\bgroup=[_a-z][-0-9_a-z]*' | cut -d '=' -f 2)
    if [ -z "${group_val}" ] || [ ${group_val} != ${var_pam_wheel_group_for_su} ]; then
        sed -Ei "s/(^auth\s+required\s+pam_wheel.so\s+[^#]*group=)[_a-z][-0-9_a-z]*/\1${var_pam_wheel_group_for_su}/" ${PAM_CONF}
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
var_user_initialization_files_regex='^\.[\w\- ]+$'


readarray -t interactive_users < <(awk -F: '$3>=1000   {print $1}' /etc/passwd)
readarray -t interactive_users_home < <(awk -F: '$3>=1000   {print $6}' /etc/passwd)
readarray -t interactive_users_shell < <(awk -F: '$3>=1000   {print $7}' /etc/passwd)

USERS_IGNORED_REGEX='nobody|nfsnobody'

for (( i=0; i<"${#interactive_users[@]}"; i++ )); do
    if ! grep -qP "$USERS_IGNORED_REGEX" <<< "${interactive_users[$i]}" && \
        [ "${interactive_users_shell[$i]}" != "/sbin/nologin" ]; then
        
        readarray -t init_files < <(find "${interactive_users_home[$i]}" -maxdepth 1 \
            -exec basename {} \; | grep -P "$var_user_initialization_files_regex")
        for file in "${init_files[@]}"; do
            chmod u-s,g-wxs,o= "${interactive_users_home[$i]}/$file"
        done
    fi
done
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "systemd-journal-remote"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'systemd-journal-upload.service'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" start 'systemd-journal-upload.service'
fi
"$SYSTEMCTL_EXEC" enable 'systemd-journal-upload.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed && { dpkg-query --show --showformat='${db:Status-Status}\n' 'systemd' 2>/dev/null | grep -q '^installed'; }; then

if [ -e "/etc/systemd/journald.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*ForwardToSyslog\s*=\s*/d" "/etc/systemd/journald.conf"
else
    touch "/etc/systemd/journald.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/systemd/journald.conf"

cp "/etc/systemd/journald.conf" "/etc/systemd/journald.conf.bak"
# Insert before the line matching the regex '^#\s*ForwardToSyslog'.
line_number="$(LC_ALL=C grep -n "^#\s*ForwardToSyslog" "/etc/systemd/journald.conf.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^#\s*ForwardToSyslog', insert at
    # the end of the file.
    printf '%s\n' "ForwardToSyslog=no" >> "/etc/systemd/journald.conf"
else
    head -n "$(( line_number - 1 ))" "/etc/systemd/journald.conf.bak" > "/etc/systemd/journald.conf"
    printf '%s\n' "ForwardToSyslog=no" >> "/etc/systemd/journald.conf"
    tail -n "+$(( line_number ))" "/etc/systemd/journald.conf.bak" >> "/etc/systemd/journald.conf"
fi
# Clean up after ourselves.
rm "/etc/systemd/journald.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

var_journal_upload_conf_file=/etc/systemd/journal-upload.conf.d/60-journald_upload.conf
mkdir -p /etc/systemd/journal-upload.conf.d
touch /etc/systemd/journal-upload.conf.d/60-journald_upload.conf

# If the key exists, comment it. Otherwise do nothing
# We search for the key string followed by a blank space,
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^ServerKeyFile[[:blank:]]" "/etc/systemd/journal-upload.conf(\.d/[^/]+\.conf)"; then
    LC_ALL=C sed -i --follow-symlinks "s/^ServerKeyFile[[:blank:]].*/#&/gi" "/etc/systemd/journal-upload.conf(\.d/[^/]+\.conf)"
fi
# If the key exists, comment it. Otherwise do nothing
# We search for the key string followed by a blank space,
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^ServerCertificateFile[[:blank:]]" "/etc/systemd/journal-upload.conf(\.d/[^/]+\.conf)"; then
    LC_ALL=C sed -i --follow-symlinks "s/^ServerCertificateFile[[:blank:]].*/#&/gi" "/etc/systemd/journal-upload.conf(\.d/[^/]+\.conf)"
fi
# If the key exists, comment it. Otherwise do nothing
# We search for the key string followed by a blank space,
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^TrustedCertificateFile[[:blank:]]" "/etc/systemd/journal-upload.conf(\.d/[^/]+\.conf)"; then
    LC_ALL=C sed -i --follow-symlinks "s/^TrustedCertificateFile[[:blank:]].*/#&/gi" "/etc/systemd/journal-upload.conf(\.d/[^/]+\.conf)"
fi


var_journal_upload_server_key_file='/etc/pki/systemd/private/journal-upload.pem'

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ServerKeyFile")

# shellcheck disable=SC2059
printf -v formatted_output "%s=%s" "$stripped_key" "$var_journal_upload_server_key_file"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^ServerKeyFile\\>" "$var_journal_upload_conf_file"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^ServerKeyFile\\>.*/$escaped_formatted_output/gi" "$var_journal_upload_conf_file"
else
    if [[ -s "$var_journal_upload_conf_file" ]] && [[ -n "$(tail -c 1 -- "$var_journal_upload_conf_file" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$var_journal_upload_conf_file"
    fi
    printf '%s\n' "$formatted_output" >> "$var_journal_upload_conf_file"
fi

var_journal_upload_server_certificate_file='/etc/pki/systemd/certs/journal-upload.pem'

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ServerCertificateFile")

# shellcheck disable=SC2059
printf -v formatted_output "%s=%s" "$stripped_key" "$var_journal_upload_server_certificate_file"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^ServerCertificateFile\\>" "$var_journal_upload_conf_file"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^ServerCertificateFile\\>.*/$escaped_formatted_output/gi" "$var_journal_upload_conf_file"
else
    if [[ -s "$var_journal_upload_conf_file" ]] && [[ -n "$(tail -c 1 -- "$var_journal_upload_conf_file" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$var_journal_upload_conf_file"
    fi
    printf '%s\n' "$formatted_output" >> "$var_journal_upload_conf_file"
fi

var_journal_upload_server_trusted_certificate_file='/etc/pki/systemd/ca/trusted.pem'

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^TrustedCertificateFile")

# shellcheck disable=SC2059
printf -v formatted_output "%s=%s" "$stripped_key" "$var_journal_upload_server_trusted_certificate_file"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^TrustedCertificateFile\\>" "$var_journal_upload_conf_file"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^TrustedCertificateFile\\>.*/$escaped_formatted_output/gi" "$var_journal_upload_conf_file"
else
    if [[ -s "$var_journal_upload_conf_file" ]] && [[ -n "$(tail -c 1 -- "$var_journal_upload_conf_file" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$var_journal_upload_conf_file"
    fi
    printf '%s\n' "$formatted_output" >> "$var_journal_upload_conf_file"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

var_journal_upload_conf_file=/etc/systemd/journal-upload.conf.d/60-journald_upload.conf
mkdir -p /etc/systemd/journal-upload.conf.d
touch /etc/systemd/journal-upload.conf.d/60-journald_upload.conf

# If the key exists, comment it. Otherwise do nothing
# We search for the key string followed by a blank space,
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^URL[[:blank:]]" "/etc/systemd/journal-upload.conf(\.d/[^/]+\.conf)"; then
    LC_ALL=C sed -i --follow-symlinks "s/^URL[[:blank:]].*/#&/gi" "/etc/systemd/journal-upload.conf(\.d/[^/]+\.conf)"
fi


var_journal_upload_url='remotelogserver'

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^URL")

# shellcheck disable=SC2059
printf -v formatted_output "%s=%s" "$stripped_key" "$var_journal_upload_url"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^URL\\>" "$var_journal_upload_conf_file"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^URL\\>.*/$escaped_formatted_output/gi" "$var_journal_upload_conf_file"
else
    if [[ -s "$var_journal_upload_conf_file" ]] && [[ -n "$(tail -c 1 -- "$var_journal_upload_conf_file" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "$var_journal_upload_conf_file"
    fi
    printf '%s\n' "$formatted_output" >> "$var_journal_upload_conf_file"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'iptables' 2>/dev/null | grep -q '^installed'; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "iptables-persistent"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

# Comment out any occurrences of net.ipv4.conf.all.rp_filter from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.rp_filter.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.rp_filter" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_all_rp_filter_value='1'


#
# Set runtime for net.ipv4.conf.all.rp_filter
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.all.rp_filter="$sysctl_net_ipv4_conf_all_rp_filter_value"
fi

#
# If net.ipv4.conf.all.rp_filter present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.rp_filter = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.rp_filter")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_rp_filter_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.rp_filter\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.rp_filter\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

# Comment out any occurrences of net.ipv4.conf.default.rp_filter from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.rp_filter.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.rp_filter" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_default_rp_filter_value='1'


#
# Set runtime for net.ipv4.conf.default.rp_filter
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.default.rp_filter="$sysctl_net_ipv4_conf_default_rp_filter_value"
fi

#
# If net.ipv4.conf.default.rp_filter present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.rp_filter = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.rp_filter")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_rp_filter_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.rp_filter\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.rp_filter\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if ( dpkg-query --show --showformat='${db:Status-Status}\n' 'nftables' 2>/dev/null | grep -q '^installed' && dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed ); then

var_network_filtering_service='nftables'


SYSTEMCTL_EXEC='/usr/bin/systemctl'

if [ $var_network_filtering_service == nftables ]; then
  "$SYSTEMCTL_EXEC" unmask 'nftables.service'
  "$SYSTEMCTL_EXEC" start 'nftables.service'
  "$SYSTEMCTL_EXEC" enable 'nftables.service'
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

# CAUTION: This remediation script will remove ufw
#	   from the system, and may remove any packages
#	   that depend on ufw. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

var_network_filtering_service='nftables'



  if [ $var_network_filtering_service != ufw ]; then
    DEBIAN_FRONTEND=noninteractive apt-get remove -y "ufw"
  fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install dccp" /etc/modprobe.d/dccp.conf ; then
	
	sed -i 's#^install dccp.*#install dccp /bin/false#g' /etc/modprobe.d/dccp.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/dccp.conf
	echo "install dccp /bin/false" >> /etc/modprobe.d/dccp.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist dccp$" /etc/modprobe.d/dccp.conf ; then
	echo "blacklist dccp" >> /etc/modprobe.d/dccp.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install rds" /etc/modprobe.d/rds.conf ; then
	
	sed -i 's#^install rds.*#install rds /bin/false#g' /etc/modprobe.d/rds.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/rds.conf
	echo "install rds /bin/false" >> /etc/modprobe.d/rds.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist rds$" /etc/modprobe.d/rds.conf ; then
	echo "blacklist rds" >> /etc/modprobe.d/rds.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install sctp" /etc/modprobe.d/sctp.conf ; then
	
	sed -i 's#^install sctp.*#install sctp /bin/false#g' /etc/modprobe.d/sctp.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/sctp.conf
	echo "install sctp /bin/false" >> /etc/modprobe.d/sctp.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist sctp$" /etc/modprobe.d/sctp.conf ; then
	echo "blacklist sctp" >> /etc/modprobe.d/sctp.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install tipc" /etc/modprobe.d/tipc.conf ; then
	
	sed -i 's#^install tipc.*#install tipc /bin/false#g' /etc/modprobe.d/tipc.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/tipc.conf
	echo "install tipc /bin/false" >> /etc/modprobe.d/tipc.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist tipc$" /etc/modprobe.d/tipc.conf ; then
	echo "blacklist tipc" >> /etc/modprobe.d/tipc.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
chgrp 0 /etc/gshadow-
chmod u-xwrs,g-xwrs,o-xwrt /etc/gshadow-
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install cramfs" /etc/modprobe.d/cramfs.conf ; then
	
	sed -i 's#^install cramfs.*#install cramfs /bin/false#g' /etc/modprobe.d/cramfs.conf
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
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install freevxfs" /etc/modprobe.d/freevxfs.conf ; then
	
	sed -i 's#^install freevxfs.*#install freevxfs /bin/false#g' /etc/modprobe.d/freevxfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/freevxfs.conf
	echo "install freevxfs /bin/false" >> /etc/modprobe.d/freevxfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist freevxfs$" /etc/modprobe.d/freevxfs.conf ; then
	echo "blacklist freevxfs" >> /etc/modprobe.d/freevxfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install hfs" /etc/modprobe.d/hfs.conf ; then
	
	sed -i 's#^install hfs.*#install hfs /bin/false#g' /etc/modprobe.d/hfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/hfs.conf
	echo "install hfs /bin/false" >> /etc/modprobe.d/hfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist hfs$" /etc/modprobe.d/hfs.conf ; then
	echo "blacklist hfs" >> /etc/modprobe.d/hfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install hfsplus" /etc/modprobe.d/hfsplus.conf ; then
	
	sed -i 's#^install hfsplus.*#install hfsplus /bin/false#g' /etc/modprobe.d/hfsplus.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/hfsplus.conf
	echo "install hfsplus /bin/false" >> /etc/modprobe.d/hfsplus.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist hfsplus$" /etc/modprobe.d/hfsplus.conf ; then
	echo "blacklist hfsplus" >> /etc/modprobe.d/hfsplus.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install jffs2" /etc/modprobe.d/jffs2.conf ; then
	
	sed -i 's#^install jffs2.*#install jffs2 /bin/false#g' /etc/modprobe.d/jffs2.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/jffs2.conf
	echo "install jffs2 /bin/false" >> /etc/modprobe.d/jffs2.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist jffs2$" /etc/modprobe.d/jffs2.conf ; then
	echo "blacklist jffs2" >> /etc/modprobe.d/jffs2.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install overlayfs" /etc/modprobe.d/overlayfs.conf ; then
	
	sed -i 's#^install overlayfs.*#install overlayfs /bin/false#g' /etc/modprobe.d/overlayfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/overlayfs.conf
	echo "install overlayfs /bin/false" >> /etc/modprobe.d/overlayfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist overlayfs$" /etc/modprobe.d/overlayfs.conf ; then
	echo "blacklist overlayfs" >> /etc/modprobe.d/overlayfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install udf" /etc/modprobe.d/udf.conf ; then
	
	sed -i 's#^install udf.*#install udf /bin/false#g' /etc/modprobe.d/udf.conf
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
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

if LC_ALL=C grep -q -m 1 "^install usb-storage" /etc/modprobe.d/usb-storage.conf ; then
	
	sed -i 's#^install usb-storage.*#install usb-storage /bin/false#g' /etc/modprobe.d/usb-storage.conf
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
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

chgrp crontab /etc/cron.allow

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

DEBIAN_FRONTEND=noninteractive apt-get remove -y "tnftp"
DEBIAN_FRONTEND=noninteractive apt-get remove -y "ftp"
# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}
' 'linux-base' 2>/dev/null | grep -q ^installed; then

var_timesync_service='systemd-timesyncd'



  if [ $var_timesync_service == systemd-timesyncd ]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "systemd-timesyncd"
  fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
