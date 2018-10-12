#!/bin/sh

if ! command -v shellcheck; then
  exit 1
fi

if ! shellcheck -x -s bash -f gcc scripts/* misc/*.sh ubuntu.sh; then
  exit 1
fi

if ! command -v vagrant; then
  exit 1
fi

rm ./*bats.log

vagrant box update --insecure
vagrant destroy --force
vagrant up --parallel

wait

for VM in $(vagrant status | grep virtualbox | awk '{print $1}' | grep -v 'basic'); do
  vagrant ssh "$VM" -c 'cp -R /vagrant ~/hardening && sed -i.bak -e "s/^AUTOFILL=.*/AUTOFILL='\''Y'\''/" -e "s/^CHANGEME=.*/CHANGEME='\''changed'\''/" ~/hardening/ubuntu.cfg && cd ~/hardening && sudo bash ubuntu.sh && sudo reboot'
done

wait

for VM in $(vagrant status | grep virtualbox | awk '{print $1}' | grep -v 'basic'); do
  vagrant ssh "$VM" -c 'sudo apt-get -y update && sudo apt-get -y install bats && cd ~/hardening/tests && sudo bats . >> ~/bats.log'
  wait
  vagrant ssh "$VM" -c 'cat ~/bats.log' | grep 'not ok'  > "hardening-$VM-$(date +%y%m%d)-bats.log"
done

wait

for VM in $(vagrant status | grep virtualbox | awk '{print $1}' | grep 'basic'); do
  vagrant ssh "$VM" -c 'cp -R /vagrant ~/hardening'
  vagrant ssh "$VM" -c 'sudo apt-get -y update && sudo apt-get -y install bats && cd ~/hardening/tests && sudo bats . >> ~/bats.log'
  wait
  vagrant ssh "$VM" -c 'cat ~/bats.log' | grep 'not ok'  > "hardening-$VM-$(date +%y%m%d)-bats.log"
done

wait

clear

find ./ -name 'hardening-*-bats.log' -type f | while read -r f; do
  if test -s "$f"; then
    echo "$f: $(grep -c '^not ok' "$f")"
  else
    echo "$f is empty, a test stage failed."
  fi
done
