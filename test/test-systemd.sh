#!/bin/bash
# site-lockdown under a real systemd, in a throwaway container that boots systemd with Apache and,
# on Rocky, firewalld. It checks that "site-lockdown on" enables and starts its units; that
# "firewall-cmd --reload" and "systemctl restart firewalld" leave the block in place, and that the
# service runs again after the restart; that the timer puts back a block that was removed; and
# that after the container restarts, booting as a server does after a reboot, the block is back
# before network-pre.target and Apache. Another container probes port 80 throughout and must never
# get in while the block is on. From the repository directory, on a Docker host (it creates and
# removes two containers, an image and a network named psw-sd-*):
#   bash test/test-systemd.sh               (Rocky 9; or name an image, such as
#   bash test/test-systemd.sh docker.io/library/ubuntu:24.04, which has nftables but no firewalld)
set -u
image=${1:-quay.io/rockylinux/rockylinux:9}
rt=${CONTAINER_RT:-docker}
id=psw-sd-$$
sys=$id-sys probe=$id-probe
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
on() { $rt exec "$sys" bash -c "$*"; }
# port 80 on the booted container as the probe sees it: OPEN, REFUSED or timeout
port80() {
    local out
    out=$($rt exec "$probe" bash -c "timeout 2 bash -c 'exec 3<>/dev/tcp/$sys/80' 2>&1 && echo OPEN")
    case $out in *OPEN*) echo OPEN ;; *refused*) echo REFUSED ;; *) echo timeout ;; esac
}
# when a unit last became active, in microseconds on the host's monotonic clock
since_boot() { on "systemctl show -p ActiveEnterTimestampMonotonic --value $1"; }
booted() {
    local i s
    for i in $(seq 1 90); do
        s=$(on 'systemctl is-system-running' 2> /dev/null)
        [[ $s == running || $s == degraded ]] && return 0
        sleep 1
    done
    echo "systemd did not finish booting: $s"; return 1
}
trap '$rt rm -f "$sys" "$probe" "$id-build" > /dev/null 2>&1; $rt rmi -f "$id-img" > /dev/null 2>&1; $rt network rm "$id" > /dev/null 2>&1' EXIT

# a container's systemd needs a cgroup v2 host (EL8's v1 with Docker doesn't boot it)
[[ -e /sys/fs/cgroup/cgroup.controllers ]] || { echo 'needs a host with cgroup v2, such as Rocky 9 or 10 or Ubuntu 22.04 and later'; exit 9; }
$rt network create "$id" > /dev/null || exit 9
# an image that boots systemd, with Apache and the firewall
$rt run -d --name "$id-build" "$image" sleep 1800 > /dev/null || exit 9
$rt exec "$id-build" bash -c 'if command -v dnf > /dev/null; then
        dnf -y -q install systemd firewalld nftables httpd perl-interpreter procps-ng iproute findutils
        systemctl enable firewalld httpd
    else
        apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq -y install systemd systemd-sysv nftables apache2 perl procps iproute2
        systemctl enable apache2
    fi > /dev/null 2>&1' || exit 9
$rt commit "$id-build" "$id-img" > /dev/null && $rt rm -f "$id-build" > /dev/null || exit 9
# container=docker: systemd 239 (Rocky 8) doesn't otherwise know it runs in a container, and shuts
# down as a whole machine would, leaving the filesystem read-only for the next boot
$rt run -d --name "$sys" --hostname "$sys" --network "$id" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --stop-signal SIGRTMIN+3 -e container=docker \
    -v "$PWD:/s:ro" "$id-img" /sbin/init > /dev/null || exit 9
$rt run -d --name "$probe" --network "$id" "$image" sleep 1800 > /dev/null || exit 9
booted || exit 9
. <(on 'cat /etc/os-release')
fw=0
on 'systemctl is-active -q firewalld' && fw=1
echo "######## $PRETTY_NAME, $(on 'systemctl --version | head -1'), $(on 'nft --version')$( ((fw)) && echo ", firewalld $(on 'firewall-cmd --version')")"
((fw)) && on 'firewall-cmd -q --permanent --add-service=http && firewall-cmd -q --reload'
on 'cd /s && bash setup.sh install' > /dev/null 2>&1
check 'before: Apache reachable' '[[ $(port80) == OPEN ]]'

echo; echo "######## on"
out=$(on 'site-lockdown on --reason "systemd test"' 2>&1)
echo "$out"
check 'blocked' '[[ $(port80) == timeout ]]'
check 'units enabled and started, nothing to warn about' '[[ $(on "systemctl is-enabled site-lockdown.service site-lockdown.timer; systemctl is-active site-lockdown.service site-lockdown.timer" | paste -sd" ") == "enabled enabled active active" ]] && ! grep -qE "no systemd|failed|not installed" <<< "$out"'

if ((fw)); then
    echo; echo "######## firewalld"
    on 'firewall-cmd -q --reload'
    check 'firewall-cmd --reload leaves the block' 'on "nft list table inet site_lockdown" > /dev/null && [[ $(port80) == timeout ]]'
    before=$(since_boot site-lockdown.service)
    on 'systemctl restart firewalld'; rc=$?
    sleep 2
    check 'systemctl restart firewalld works while the block is on' '((rc == 0)) && on "systemctl is-active -q firewalld"'
    check 'and runs site-lockdown.service again' '[[ $(since_boot site-lockdown.service) != "$before" ]]'
    check 'the block is still there' 'on "nft list table inet site_lockdown" > /dev/null && [[ $(port80) == timeout ]]'
fi

echo; echo "######## the timer"
on 'nft delete table inet site_lockdown'
check 'with the table removed, Apache is reachable' '[[ $(port80) == OPEN ]]'
for i in $(seq 1 15); do sleep 5; on 'nft list table inet site_lockdown' > /dev/null 2>&1 && break; done
echo "back after about $((i * 5)) s"
check 'the timer puts the block back within a minute or so' 'on "nft list table inet site_lockdown" > /dev/null 2>&1 && [[ $(port80) == timeout ]] && on "grep -q \"restored the block\" /var/log/site-lockdown.log"'

echo; echo "######## a reboot"
# the probe tries port 80 four times a second from before the restart until the checks are done
$rt exec -d "$probe" bash -c "echo \$\$ > /tmp/probe.pid; while :; do
    if timeout 1 bash -c 'exec 3<>/dev/tcp/$sys/80' 2> /dev/null; then echo \"\$(date +%T.%N | cut -c1-12) OPEN\"; fi
    sleep 0.25
done > /tmp/probe.log 2>&1"
sleep 1
on 'echo -n > /var/log/site-lockdown.log'
$rt restart -t 30 "$sys" > /dev/null || exit 9
booted || exit 9
log=$(on 'cat /var/log/site-lockdown.log')
echo "$log"
check 'the block came back at boot' '[[ $(on "site-lockdown status" | head -1) == "lockdown: on" ]] && grep -q "restored the block, whose rules were gone" <<< "$log"'
sl=$(since_boot site-lockdown.service) pre=$(since_boot network-pre.target) web=$(since_boot "$( ((fw)) && echo httpd || echo apache2).service")
echo "after site-lockdown.service: network-pre.target +$(((pre - sl) / 1000)) ms, Apache +$(((web - sl) / 1000)) ms$( ((fw)) && echo ", and firewalld $(((sl - $(since_boot firewalld.service)) / 1000)) ms before it")"
check 'before network-pre.target and Apache' '((sl > 0 && sl <= pre && sl < web))'
((fw)) && check 'and after firewalld' '(($(since_boot firewalld.service) < sl))'
check 'Apache is up and still blocked' 'on "systemctl is-active -q $( ((fw)) && echo httpd || echo apache2)" && [[ $(port80) == timeout ]]'
$rt exec "$probe" bash -c 'kill "$(cat /tmp/probe.pid)"' 
opened=$($rt exec "$probe" cat /tmp/probe.log)
check 'the probe never got in during the restart' '[[ -z $opened ]] || { echo "$opened" | head -5; false; }'

echo; echo "######## off"
on 'site-lockdown off' > /dev/null
check 'off: reachable, units disabled' '[[ $(port80) == OPEN ]] && [[ $(on "systemctl is-enabled site-lockdown.service site-lockdown.timer" | paste -sd" ") == "disabled disabled" ]]'

echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all systemd tests passed'
exit $fail
