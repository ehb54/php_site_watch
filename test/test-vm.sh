#!/bin/bash
# site-lockdown on a real VM, rebooted. Boots a cloud image in QEMU, with cloud-init installing
# Apache and, on Rocky, firewalld, and installs this checkout. Then, from the host, through QEMU's
# port forwarding:
# - "site-lockdown on" blocks Apache;
# - "systemctl restart firewalld" works and keeps the block (Rocky);
# - after a real reboot the block is back before Apache, firewalld and NetworkManager have let
#   anything in: the host asks for a page four times a second from before the reboot until it is
#   done and must never get one;
# - "site-lockdown off" opens it again.
# From the repository directory, on a Linux host with KVM, QEMU and genisoimage. It downloads the
# cloud image into $PSW_VM_CACHE (default ~/.cache/psw-vm) and removes everything else it creates:
#   bash test/test-vm.sh rocky9          (or rocky8, rocky10, ubuntu24.04)
set -u
name=${1:-rocky9}
case $name in
    rocky8 | rocky9 | rocky10)
        url=https://dl.rockylinux.org/pub/rocky/${name#rocky}/images/x86_64/Rocky-${name#rocky}-GenericCloud-Base.latest.x86_64.qcow2
        web=httpd packages='[httpd, firewalld, nftables, perl-interpreter]' ;;
    ubuntu24.04)
        url=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
        web=apache2 packages='[apache2, nftables, perl]' ;;
    *) echo "unknown image $name: rocky8, rocky9, rocky10 or ubuntu24.04"; exit 9 ;;
esac
qemu=$(command -v qemu-system-x86_64 || command -v /usr/libexec/qemu-kvm) || { echo 'needs QEMU'; exit 9; }
[[ -w /dev/kvm ]] || { echo 'needs /dev/kvm (read and write)'; exit 9; }
command -v genisoimage > /dev/null || { echo 'needs genisoimage'; exit 9; }
cache=${PSW_VM_CACHE:-$HOME/.cache/psw-vm}
t=$(mktemp -d)
sshport=$((20000 + $$ % 20000)) webport=$((40000 + $$ % 20000))
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
# QEMU's user networking keeps the host's end of a connection open when the guest goes away, so
# give up on a silent connection rather than wait for it
vm() { ssh -q -i "$t/key" -p "$sshport" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 tester@127.0.0.1 "$@"; }
# what the host gets from Apache in the VM: an HTTP status, or 000 for nothing
page() { curl -s -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$webport/"; }
up() {
    local i
    for i in $(seq 1 120); do vm true 2> /dev/null && return 0; sleep 3; done
    echo "the VM did not come up; its console:"; tail -20 "$t/console.log"; return 1
}
since_boot() { vm "systemctl show -p ActiveEnterTimestampMonotonic --value $1"; }
trap '[[ -s $t/qemu.pid ]] && kill "$(cat "$t/qemu.pid")" 2> /dev/null; rm -rf "$t"' EXIT

mkdir -p "$cache"
if [[ ! -s $cache/$name.qcow2 ]]; then
    curl -fsSL -o "$cache/$name.qcow2.part" "$url" && mv "$cache/$name.qcow2.part" "$cache/$name.qcow2" || { echo "cannot download $url"; exit 9; }
fi
qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$name.qcow2" "$t/disk.qcow2" 20G || exit 9
ssh-keygen -q -t ed25519 -N '' -f "$t/key"
cat > "$t/user-data" <<EOF
#cloud-config
users:
  - name: tester
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: ["$(cat "$t/key.pub")"]
packages: $packages
runcmd:
  - echo ok > /var/www/html/index.html
  - systemctl enable --now $web
  - if command -v firewall-cmd; then systemctl enable --now firewalld && firewall-cmd --permanent --add-service=http && firewall-cmd --reload; fi
EOF
printf 'instance-id: psw-%s\nlocal-hostname: psw-%s\n' $$ "$name" > "$t/meta-data"
genisoimage -quiet -output "$t/seed.iso" -volid cidata -joliet -rock "$t/user-data" "$t/meta-data" || exit 9
"$qemu" -enable-kvm -cpu host -m 2048 -smp 2 -display none -serial "file:$t/console.log" -monitor none \
    -drive "file=$t/disk.qcow2,if=virtio" -cdrom "$t/seed.iso" \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$sshport-:22,hostfwd=tcp:127.0.0.1:$webport-:80" \
    -device virtio-net-pci,netdev=n0 -pidfile "$t/qemu.pid" -daemonize || exit 9
up || exit 9
vm 'sudo cloud-init status --wait' > /dev/null 2>&1
fw=0
vm 'systemctl is-active -q firewalld' && fw=1
echo "######## $(vm '. /etc/os-release; echo $PRETTY_NAME'), kernel $(vm 'uname -r'), $(vm 'systemctl --version | head -1')$( ((fw)) && echo ", firewalld $(vm 'sudo firewall-cmd --version')")"
tar -czf - --exclude .git . | vm 'mkdir -p psw && tar -C psw -xzf - && cd psw && sudo bash setup.sh install' > /dev/null 2>&1
check 'installed, and Apache answers' '[[ $(vm "/usr/local/sbin/site-lockdown --version") == site-lockdown* && $(page) == 200 ]]'

echo; echo "######## on"
vm 'sudo /usr/local/sbin/site-lockdown on --reason "VM test"'
check 'blocked' '[[ $(page) == 000 ]]'
check 'units enabled and started' '[[ $(vm "systemctl is-enabled site-lockdown.service site-lockdown.timer; systemctl is-active site-lockdown.service site-lockdown.timer" | paste -sd" ") == "enabled enabled active active" ]]'
if ((fw)); then
    before=$(since_boot site-lockdown.service)
    vm 'sudo systemctl restart firewalld'; rc=$?
    check 'systemctl restart firewalld works and runs site-lockdown.service again' '((rc == 0)) && [[ $(since_boot site-lockdown.service) != "$before" ]]'
    check 'still blocked' '[[ $(page) == 000 ]]'
fi

echo; echo "######## reboot"
# from before the reboot until the checks are done, ask for a page four times a second
( while [[ ! -e $t/stop ]]; do
      [[ $(page) == 200 ]] && date +%T.%N | cut -c1-12 >> "$t/got-in"
      sleep 0.25
  done ) &
sleep 1
# a new boot has a new boot ID; SSH can still answer for a moment while the old system shuts down
boot_id=$(vm 'cat /proc/sys/kernel/random/boot_id')
vm 'sudo systemd-run --quiet --on-active=1 systemctl reboot' 2> /dev/null    # a second from now, after this returns
for i in $(seq 1 120); do
    sleep 3
    now_id=$(vm 'cat /proc/sys/kernel/random/boot_id' 2> /dev/null)
    [[ -n $now_id && $now_id != "$boot_id" ]] && break
done
[[ -n $now_id && $now_id != "$boot_id" ]] || { echo 'the VM did not come back from the reboot; its console:'; tail -20 "$t/console.log"; exit 9; }
vm 'sudo systemctl is-system-running --wait' > /dev/null 2>&1
check 'the block came back at boot' '[[ $(vm "sudo /usr/local/sbin/site-lockdown status" | head -1) == "lockdown: on" ]] && vm "sudo tail -1 /var/log/site-lockdown.log" | grep -q "restored the block, whose rules were gone"'
sl=$(since_boot site-lockdown.service) pre=$(since_boot network-pre.target) ws=$(since_boot $web.service)
echo "boot: site-lockdown.service at $((sl / 1000)) ms, network-pre.target +$(((pre - sl) / 1000)) ms, $web +$(((ws - sl) / 1000)) ms$( ((fw)) && echo ", firewalld $(((sl - $(since_boot firewalld.service)) / 1000)) ms before it")"
check 'before network-pre.target and Apache' '((sl > 0 && sl <= pre && sl < ws))'
((fw)) && check 'and after firewalld' '(($(since_boot firewalld.service) < sl))'
check 'Apache is up and blocked' 'vm "systemctl is-active -q $web" && [[ $(page) == 000 ]]'
touch "$t/stop"; wait
check 'the host never got a page during the reboot' '[[ ! -s $t/got-in ]] || { head -5 "$t/got-in"; false; }'

echo; echo "######## off"
vm 'sudo /usr/local/sbin/site-lockdown off' > /dev/null
check 'off: Apache answers again' '[[ $(page) == 200 ]]'

echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all VM tests passed'
exit $fail
