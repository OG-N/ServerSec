#!/bin/bash
# -----------------------------------------------------------------------------
# Ubuntu 22.04 LTS - Basic Soft Hardening - root
# Install & Setup: User Account, OpenSSH, UFW, Fail2Ban, Security Update
# ---------------------------------------------------------------------------
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed && { ! ( grep -q aarch64 /proc/sys/kernel/osrelease ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="chown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchmod"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchmodat"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchmodat"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchmodat"
	KEY="perm_mod"
	SYSCALL_GROUPING="chmod fchmod fchmodat"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fchownat"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fremovexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="fsetxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed && { ! ( grep -q aarch64 /proc/sys/kernel/osrelease ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lchown"
	KEY="perm_mod"
	SYSCALL_GROUPING="chown fchown fchownat lchown"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lremovexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="lsetxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="removexattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="setxattr"
	KEY="perm_mod"
	SYSCALL_GROUPING="fremovexattr lremovexattr removexattr fsetxattr lsetxattr setxattr"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/chacl -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/bin/setfacl -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed && { ! ( grep -q aarch64 /proc/sys/kernel/osrelease ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="rename"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="renameat"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed && { ! ( grep -q aarch64 /proc/sys/kernel/osrelease ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="unlink"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="unlinkat"
	KEY="delete"
	SYSCALL_GROUPING="unlink unlinkat rename renameat rmdir"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed && { ! ( grep -q aarch64 /proc/sys/kernel/osrelease ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="creat"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EPERM"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="ftruncate"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EPERM"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed && { ! ( grep -q aarch64 /proc/sys/kernel/osrelease ); }; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="open"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EPERM"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="openat"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EPERM"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL="truncate"
KEY="access"
SYSCALL_GROUPING="creat ftruncate truncate open openat open_by_handle_at"

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EACCES"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F exit=-EPERM"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	
	SYSCALL="delete_module"
	KEY="modules"
	SYSCALL_GROUPING="delete_module"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	
	SYSCALL="init_module"
	KEY="modules"
	SYSCALL_GROUPING="init_module finit_module"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

ACTION_ARCH_FILTERS="-a always,exit"
OTHER_FILTERS="-F path=/usr/sbin/usermod -F perm=x"
AUID_FILTERS="-F auid>=1000 -F auid!=unset"
SYSCALL=""
KEY="privileged"
SYSCALL_GROUPING=""
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS="-F a0=0x0"
	AUID_FILTERS=""
	SYSCALL="clock_settime"
	KEY="time-change"
	SYSCALL_GROUPING=""
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/selinux/" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/selinux/ $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/selinux/$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/selinux/ -p wa -k MAC-policy" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/MAC-policy.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/selinux/" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/MAC-policy.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/MAC-policy.rules"
    # If the MAC-policy.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/selinux/" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/selinux/ $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/selinux/$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/selinux/ -p wa -k MAC-policy" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	OTHER_FILTERS=""
	AUID_FILTERS="-F auid>=1000 -F auid!=unset"
	SYSCALL="mount"
	KEY="perm_mod"
	SYSCALL_GROUPING=""

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	
	OTHER_FILTERS="-C uid!=euid -F euid=0"
	
	AUID_FILTERS=""
	SYSCALL="execve"
	KEY="setuid"
	SYSCALL_GROUPING=""
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

for ARCH in "${RULE_ARCHS[@]}"
do
	ACTION_ARCH_FILTERS="-a always,exit -F arch=$ARCH"
	
	OTHER_FILTERS="-C gid!=egid -F egid=0"
	
	AUID_FILTERS=""
	SYSCALL="execve"
	KEY="setgid"
	SYSCALL_GROUPING=""
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()

# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
default_file="/etc/audit/rules.d/$KEY.rules"
# As other_filters may include paths, lets use a different delimiter for it
# The "F" script expression tells sed to print the filenames where the expressions matched
readarray -t files_to_inspect < <(sed -s -n -e "/^$ACTION_ARCH_FILTERS/!d" -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" -e "F" /etc/audit/rules.d/*.rules)
# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
if [ ${#files_to_inspect[@]} -eq "0" ]
then
    file_to_inspect="/etc/audit/rules.d/$KEY.rules"
    files_to_inspect=("$file_to_inspect")
    if [ ! -e "$file_to_inspect" ]
    then
        touch "$file_to_inspect"
        chmod 0640 "$file_to_inspect"
    fi
fi

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
	unset syscall_a
unset syscall_grouping
unset syscall_string
unset syscall
unset file_to_edit
unset rule_to_edit
unset rule_syscalls_to_edit
unset other_string
unset auid_string
unset full_rule

# Load macro arguments into arrays
read -a syscall_a <<< $SYSCALL
read -a syscall_grouping <<< $SYSCALL_GROUPING

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
files_to_inspect=()


# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
default_file="/etc/audit/audit.rules"
files_to_inspect+=('/etc/audit/audit.rules' )

# After converting to jinja, we cannot return; therefore we skip the rest of the macro if needed instead
skip=1

for audit_file in "${files_to_inspect[@]}"
do
    # Filter existing $audit_file rules' definitions to select those that satisfy the rule pattern,
    # i.e, collect rules that match:
    # * the action, list and arch, (2-nd argument)
    # * the other filters, (3-rd argument)
    # * the auid filters, (4-rd argument)
    readarray -t similar_rules < <(sed -e "/^$ACTION_ARCH_FILTERS/!d"  -e "\#$OTHER_FILTERS#!d" -e "/$AUID_FILTERS/!d" "$audit_file")

    candidate_rules=()
    # Filter out rules that have more fields then required. This will remove rules more specific than the required scope
    for s_rule in "${similar_rules[@]}"
    do
        # Strip all the options and fields we know of,
        # than check if there was any field left over
        extra_fields=$(sed -E -e "s/^$ACTION_ARCH_FILTERS//"  -e "s#$OTHER_FILTERS##" -e "s/$AUID_FILTERS//" -e "s/((:?-S [[:alnum:],]+)+)//g" -e "s/-F key=\w+|-k \w+//"<<< "$s_rule")
        grep -q -- "-F" <<< "$extra_fields" || candidate_rules+=("$s_rule")
    done

    if [[ ${#syscall_a[@]} -ge 1 ]]
    then
        # Check if the syscall we want is present in any of the similar existing rules
        for rule in "${candidate_rules[@]}"
        do
            rule_syscalls=$(echo "$rule" | grep -o -P '(-S [\w,]+)+' | xargs)
            all_syscalls_found=0
            for syscall in "${syscall_a[@]}"
            do
                grep -q -- "\b${syscall}\b" <<< "$rule_syscalls" || {
                   # A syscall was not found in the candidate rule
                   all_syscalls_found=1
                   }
            done
            if [[ $all_syscalls_found -eq 0 ]]
            then
                # We found a rule with all the syscall(s) we want; skip rest of macro
                skip=0
                break
            fi

            # Check if this rule can be grouped with our target syscall and keep track of it
            for syscall_g in "${syscall_grouping[@]}"
            do
                if grep -q -- "\b${syscall_g}\b" <<< "$rule_syscalls"
                then
                    file_to_edit=${audit_file}
                    rule_to_edit=${rule}
                    rule_syscalls_to_edit=${rule_syscalls}
                fi
            done
        done
    else
        # If there is any candidate rule, it is compliant; skip rest of macro
        if [ "${#candidate_rules[@]}" -gt 0 ]
        then
            skip=0
        fi
    fi

    if [ "$skip" -eq 0 ]; then
        break
    fi
done

if [ "$skip" -ne 0 ]; then
    # We checked all rules that matched the expected resemblance pattern (action, arch & auid)
    # At this point we know if we need to either append the $full_rule or group
    # the syscall together with an exsiting rule

    # Append the full_rule if it cannot be grouped to any other rule
    if [ -z ${rule_to_edit+x} ]
    then
        # Build full_rule while avoid adding double spaces when other_filters is empty
        if [ "${#syscall_a[@]}" -gt 0 ]
        then
            syscall_string=""
            for syscall in "${syscall_a[@]}"
            do
                syscall_string+=" -S $syscall"
            done
        fi
        other_string=$([[ $OTHER_FILTERS ]] && echo " $OTHER_FILTERS") || /bin/true
        auid_string=$([[ $AUID_FILTERS ]] && echo " $AUID_FILTERS") || /bin/true
        full_rule="$ACTION_ARCH_FILTERS${syscall_string}${other_string}${auid_string} -F key=$KEY" || /bin/true
        echo "$full_rule" >> "$default_file"
        chmod o-rwx ${default_file}
    else
        # Check if the syscalls are declared as a comma separated list or
        # as multiple -S parameters
        if grep -q -- "," <<< "${rule_syscalls_to_edit}"
        then
            delimiter=","
        else
            delimiter=" -S "
        fi
        new_grouped_syscalls="${rule_syscalls_to_edit}"
        for syscall in "${syscall_a[@]}"
        do
            grep -q -- "\b${syscall}\b" <<< "${rule_syscalls_to_edit}" || {
               # A syscall was not found in the candidate rule
               new_grouped_syscalls+="${delimiter}${syscall}"
               }
        done

        # Group the syscall in the rule
        sed -i -e "\#${rule_to_edit}#s#${rule_syscalls_to_edit}#${new_grouped_syscalls}#" "$file_to_edit"
    fi
fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers -p wa -k actions" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/actions.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/sudoers" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/actions.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/actions.rules"
    # If the actions.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers -p wa -k actions" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers.d/" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers.d/ $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers.d/$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers.d/ -p wa -k actions" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/actions.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/etc/sudoers.d/" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/actions.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/actions.rules"
    # If the actions.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/etc/sudoers.d/" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/etc/sudoers.d/ $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/etc/sudoers.d/$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /etc/sudoers.d/ -p wa -k actions" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && dpkg-query --show --showformat='${db:Status-Status}\n' 'auditd' 2>/dev/null | grep -q installed; then

# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'


# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()


# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
files_to_inspect+=('/etc/audit/audit.rules')

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/sudo.log" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/sudo.log $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/sudo.log$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/sudo.log -p wa -k logins" >> "$audit_rules_file"
    fi
done
# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
files_to_inspect=()

# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/logins.rules' to list of files for inspection.
readarray -t matches < <(grep -HP "[\s]*-w[\s]+/var/log/sudo.log" /etc/audit/rules.d/*.rules)

# For each of the matched entries
for match in "${matches[@]}"
do
    # Extract filepath from the match
    rulesd_audit_file=$(echo $match | cut -f1 -d ':')
    # Append that path into list of files for inspection
    files_to_inspect+=("$rulesd_audit_file")
done
# Case when particular audit rule isn't defined yet
if [ "${#files_to_inspect[@]}" -eq "0" ]
then
    # Append '/etc/audit/rules.d/logins.rules' into list of files for inspection
    key_rule_file="/etc/audit/rules.d/logins.rules"
    # If the logins.rules file doesn't exist yet, create it with correct permissions
    if [ ! -e "$key_rule_file" ]
    then
        touch "$key_rule_file"
        chmod 0640 "$key_rule_file"
    fi
    files_to_inspect+=("$key_rule_file")
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do
    # Check if audit watch file system object rule for given path already present
    if grep -q -P -- "^[\s]*-w[\s]+/var/log/sudo.log" "$audit_rules_file"
    then
        # Rule is found => verify yet if existing rule definition contains
        # all of the required access type bits

        # Define BRE whitespace class shortcut
        sp="[[:space:]]"
        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
        current_access_bits=$(sed -ne "s#$sp*-w$sp\+/var/log/sudo.log $sp\+-p$sp\+\([rxwa]\{1,4\}\).*#\1#p" "$audit_rules_file")
        # Split required access bits string into characters array
        # (to check bit's presence for one bit at a time)
        for access_bit in $(echo "wa" | grep -o .)
        do
            # For each from the required access bits (e.g. 'w', 'a') check
            # if they are already present in current access bits for rule.
            # If not, append that bit at the end
            if ! grep -q "$access_bit" <<< "$current_access_bits"
            then
                # Concatenate the existing mask with the missing bit
                current_access_bits="$current_access_bits$access_bit"
            fi
        done
        # Propagate the updated rule's access bits (original + the required
        # ones) back into the /etc/audit/audit.rules file for that rule
        sed -i "s#\($sp*-w$sp\+/var/log/sudo.log$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)#\1$current_access_bits\3#" "$audit_rules_file"
    else
        # Rule isn't present yet. Append it at the end of $audit_rules_file file
        # with proper key

        echo "-w /var/log/sudo.log -p wa -k logins" >> "$audit_rules_file"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of net.ipv4.conf.default.rp_filter from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.rp_filter.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.rp_filter" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
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
/sbin/sysctl -q -n -w net.ipv4.conf.default.rp_filter="$sysctl_net_ipv4_conf_default_rp_filter_value"

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
if ( dpkg-query --show --showformat='${db:Status-Status}\n' 'nftables' 2>/dev/null | grep -q installed ); then

var_nftables_master_config_file='/etc/nftables.conf'


var_nftables_family='inet'


if [ ! -f "${var_nftables_master_config_file}" ]; then
    touch "${var_nftables_master_config_file}"
fi

nft list ruleset > "/etc/${var_nftables_family}-filter.rules"

grep -qxF 'include "/etc/'"${var_nftables_family}"'-filter.rules"' "${var_nftables_master_config_file}" \
    || echo 'include "/etc/'"${var_nftables_family}"'-filter.rules"' >> "${var_nftables_master_config_file}"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
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

# Comment out any occurrences of net.ipv4.conf.default.rp_filter from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.rp_filter.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.rp_filter" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
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
/sbin/sysctl -q -n -w net.ipv4.conf.default.rp_filter="$sysctl_net_ipv4_conf_default_rp_filter_value"

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
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

DEBIAN_FRONTEND=noninteractive apt-get install -y "systemd-journal-remote"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { dpkg-query --show --showformat='${db:Status-Status}\n' 'grub2-common' 2>/dev/null | grep -q installed; }; then

# Correct the form of default kernel command line in GRUB
if grep -q '^\s*GRUB_CMDLINE_LINUX=.*audit=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an audit= arg already exists
       sed -i "s/\(^\s*GRUB_CMDLINE_LINUX=\".*\)audit=[^[:space:]]\+\(.*\"\)/\1audit=1\2/"  '/etc/default/grub'
# Add to already existing GRUB_CMDLINE_LINUX parameters
elif grep -q '^\s*GRUB_CMDLINE_LINUX='  '/etc/default/grub' ; then
       # no audit=arg is present, append it
       sed -i "s/\(^\s*GRUB_CMDLINE_LINUX=\".*\)\"/\1 audit=1\"/"  '/etc/default/grub'
# Add GRUB_CMDLINE_LINUX parameters line
else
       echo "GRUB_CMDLINE_LINUX=\"audit=1\"" >> '/etc/default/grub'
fi
update-grub

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install dccp" /etc/modprobe.d/dccp.conf ; then
	
	sed -i 's#^install dccp.*#install dccp /bin/true#g' /etc/modprobe.d/dccp.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/dccp.conf
	echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist dccp$" /etc/modprobe.d/dccp.conf ; then
	echo "blacklist dccp" >> /etc/modprobe.d/dccp.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install rds" /etc/modprobe.d/rds.conf ; then
	
	sed -i 's#^install rds.*#install rds /bin/true#g' /etc/modprobe.d/rds.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/rds.conf
	echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist rds$" /etc/modprobe.d/rds.conf ; then
	echo "blacklist rds" >> /etc/modprobe.d/rds.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install sctp" /etc/modprobe.d/sctp.conf ; then
	
	sed -i 's#^install sctp.*#install sctp /bin/true#g' /etc/modprobe.d/sctp.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/sctp.conf
	echo "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist sctp$" /etc/modprobe.d/sctp.conf ; then
	echo "blacklist sctp" >> /etc/modprobe.d/sctp.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install tipc" /etc/modprobe.d/tipc.conf ; then
	
	sed -i 's#^install tipc.*#install tipc /bin/true#g' /etc/modprobe.d/tipc.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/tipc.conf
	echo "install tipc /bin/true" >> /etc/modprobe.d/tipc.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist tipc$" /etc/modprobe.d/tipc.conf ; then
	echo "blacklist tipc" >> /etc/modprobe.d/tipc.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

find / -xdev -type f -perm -002 -exec chmod o-w {} \;
find -H /var/log/  -perm /u+xs,g+xws,o+xwrt ! -name 'history.log' ! -name 'eipp.log.xz' ! -name '*[bw]tmp' ! -name '*lastlog' -type f -regex '.*' -exec chmod u-xs,g-xws,o-xwrt {} \;
find / -xdev -type f -perm -002 -exec chmod o-w {} \;
- name: Find /var/log/ file(s) recursively
  command: find -H /var/log/  -perm /u+xs,g+xws,o+xwrt ! -name "history.log" ! -name
    "eipp.log.xz" ! -name "*[bw]tmp" ! -name "*lastlog" -type f -regex ".*"
  register: files_found
  changed_when: false
  failed_when: false
  check_mode: false
  tags:
  - NIST-800-53-SI-11(a)
  - NIST-800-53-SI-11(b)
  - NIST-800-53-SI-11.1(iii)
  - PCI-DSSv4-10.3.1
  - configure_strategy
  - low_complexity
  - low_disruption
  - medium_severity
  - no_reboot_needed
  - permissions_local_var_log

- name: Set permissions for /var/log/ file(s)
  file:
    path: '{{ item }}'
    mode: u-xs,g-xws,o-xwrt
    state: file
  with_items:
  - '{{ files_found.stdout_lines }}'
  tags:
  - NIST-800-53-SI-11(a)
  - NIST-800-53-SI-11(b)
  - NIST-800-53-SI-11.1(iii)
  - PCI-DSSv4-10.3.1
  - configure_strategy
  - low_complexity
  - low_disruption
  - medium_severity
  - no_reboot_needed
  - permissions_local_var_log
  # Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install cramfs" /etc/modprobe.d/cramfs.conf ; then
	
	sed -i 's#^install cramfs.*#install cramfs /bin/true#g' /etc/modprobe.d/cramfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/cramfs.conf
	echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf
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
	echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf
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
	echo "install udf /bin/true" >> /etc/modprobe.d/udf.conf
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
	echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb-storage.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist usb-storage$" /etc/modprobe.d/usb-storage.conf ; then
	echo "blacklist usb-storage" >> /etc/modprobe.d/usb-storage.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of fs.suid_dumpable from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*fs.suid_dumpable.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "fs.suid_dumpable" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for fs.suid_dumpable
#
/sbin/sysctl -q -n -w fs.suid_dumpable="0"

#
# If fs.suid_dumpable present in /etc/sysctl.conf, change value to "0"
#	else, add "fs.suid_dumpable = 0" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^fs.suid_dumpable")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^fs.suid_dumpable\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^fs.suid_dumpable\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
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
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Comment out any occurrences of fs.suid_dumpable from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do

  matching_list=$(grep -P '^(?!#).*[\s]*fs.suid_dumpable.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "fs.suid_dumpable" matches to preserve user data
      sed -i "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for fs.suid_dumpable
#
/sbin/sysctl -q -n -w fs.suid_dumpable="0"

#
# If fs.suid_dumpable present in /etc/sysctl.conf, change value to "0"
#	else, add "fs.suid_dumpable = 0" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^fs.suid_dumpable")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^fs.suid_dumpable\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^fs.suid_dumpable\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
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

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*HostbasedAuthentication\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "HostbasedAuthentication no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*IgnoreRhosts\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "IgnoreRhosts yes" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*PermitRootLogin\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "PermitRootLogin no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*AllowTcpForwarding\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "AllowTcpForwarding no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*AllowTcpForwarding\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "AllowTcpForwarding no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*X11Forwarding\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "X11Forwarding no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*PermitUserEnvironment\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "PermitUserEnvironment no" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*Banner\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "Banner /etc/issue.net" > "/etc/ssh/sshd_config"
cat "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"

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

if [ -e "/etc/ssh/sshd_config" ] ; then
    
    LC_ALL=C sed -i "/^\s*LogLevel\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/ssh/sshd_config"

cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert at the beginning of the file
printf '%s\n' "LogLevel INFO" > "/etc/ssh/sshd_config"
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
fi# Remediation is applicable only in certain platforms
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

sshd_strong_kex='ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256'


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

else
    >&2 echo 'Remediation is not applicable, nothing was done'
