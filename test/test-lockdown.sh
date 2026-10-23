#!/bin/bash
# site-lockdown and fleet-agent in throwaway containers on a network of their own: a server with
# nftables, sshd and sudo, a control host (c1) and another client (c2). From outside it checks the
# block (web ports, MySQL only on request, a port published through address translation as Docker
# does, never SSH), the allowed addresses, enforce after the rules are removed or flushed, and
# fleet-agent over SSH: what a control host may and may not do, its from= limit, the health lines
# in php-site-watch, and removing it. From the repository directory, on a machine with podman or
# docker (it creates and removes three containers and a network named psw-lock-*):
#   bash test/test-lockdown.sh                    (Rocky 9; or name another image, such as
#   bash test/test-lockdown.sh quay.io/rockylinux/rockylinux:8   or   docker.io/library/ubuntu:20.04)
set -u
image=${1:-quay.io/rockylinux/rockylinux:9}
# CONTAINER_RT=docker picks docker where both are installed, as on GitHub's runners
rt=${CONTAINER_RT:-$(command -v podman || command -v docker)} || { echo 'needs podman or docker'; exit 9; }
id=psw-lock-$$
srv=$id-srv c1=$id-c1 c2=$id-c2
t=$(mktemp -d)
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
on() { local c=$1; shift; $rt exec "$c" bash -c "$*"; }
# what a client gets from a port on the server: the listener's greeting, or nothing
probe() { on "$1" "timeout 3 bash -c 'exec 3<>/dev/tcp/$sip/$2 && head -1 <&3' 2> /dev/null"; }
reach() { [[ $(probe "$1" "$2") == "port $3" ]]; }
blocked() { [[ -z $(probe "$1" "$2") ]]; }
fleet() { local c=$1; shift; on "$c" "ssh -i /root/ctl -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 fleet@$sip $*" 2>&1; }
trap '$rt rm -f "$srv" "$c1" "$c2" > /dev/null 2>&1; $rt network rm "$id" > /dev/null 2>&1; rm -rf "$t"' EXIT

$rt network create "$id" > /dev/null || exit 9
$rt run -d --name "$srv" --network "$id" --cap-add NET_ADMIN -v "$PWD:/s:ro,z" "$image" sleep 1800 > /dev/null || exit 9
for c in "$c1" "$c2"; do
    $rt run -d --name "$c" --network "$id" "$image" sleep 1800 > /dev/null || exit 9
done
for c in "$srv" "$c1" "$c2"; do
    on "$c" 'if command -v dnf > /dev/null; then
                 dnf -y -q install perl-interpreter nftables openssh-server openssh-clients sudo procps-ng iproute findutils util-linux
             else
                 apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq -y install perl nftables openssh-server openssh-client sudo procps iproute2
             fi > /dev/null 2>&1' &
done
wait
ip_of() { $rt inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
sip=$(ip_of "$srv") ip1=$(ip_of "$c1") ip2=$(ip_of "$c2")
. <(on "$srv" 'cat /etc/os-release')
echo "######## $PRETTY_NAME, $(on "$srv" 'nft --version'), server $sip, control host $ip1, other client $ip2"

# the server: setup.sh install, sshd, and listeners that answer "port N"; 443 reaches its
# listener on 8443 only through address translation, like a port Docker publishes
on "$srv" 'cd /s && bash setup.sh install' > $t/install.txt 2>&1
check 'setup.sh install puts site-lockdown and fleet-agent in place' \
    'grep -q "installed /usr/local/sbin/site-lockdown and /usr/local/sbin/fleet-agent" $t/install.txt && on "$srv" "site-lockdown --version && fleet-agent --version" > /dev/null'
settings=$(on "$srv" 'grep -cvE "^[[:space:]]*(#|\$)" /etc/site-lockdown.conf')
check 'and a commented /etc/site-lockdown.conf' '[[ $settings == 0 ]]'
on "$srv" 'ssh-keygen -A > /dev/null; mkdir -p /run/sshd
           sed -i "/pam_loginuid/s/^/#/" /etc/pam.d/sshd    # containers cannot set the login uid
           rm -f /run/nologin    # left by the Rocky 8 image, as if still booting; it keeps out all but root
           /usr/sbin/sshd
           # a stand-in logger, so the test can see what goes to syslog
           printf "#!/bin/sh\necho \"\$*\" >> /var/log/test-syslog\n" > /usr/local/bin/logger; chmod 755 /usr/local/bin/logger
           touch /var/log/test-syslog; chmod 666 /var/log/test-syslog
           for p in 80 3306 8080 8443; do
               setsid perl -MIO::Socket::INET -e "\$s = IO::Socket::INET->new(LocalPort => $p, Listen => 9, ReuseAddr => 1) or die; while (\$c = \$s->accept) { print \$c \"port $p\\n\"; close \$c }" < /dev/null > /dev/null 2>&1 &
           done
           nft add table ip natsim
           nft "add chain ip natsim pre { type nat hook prerouting priority -100; }"
           nft add rule ip natsim pre tcp dport 443 dnat to '"$sip"':8443' > /dev/null 2>&1
sleep 1
nat=1
reach "$c1" 443 8443 || { nat=0; echo "(address translation is not available here; skipping those checks)"; }

echo; echo "######## before: everything reachable"
check 'web, MySQL, other ports and SSH reachable' 'reach "$c1" 80 80 && reach "$c1" 3306 3306 && reach "$c1" 8080 8080 && [[ $(probe "$c1" 22) == SSH-* ]]'
check 'status: off' '[[ $(on "$srv" "site-lockdown status") == "lockdown: off" ]]'
check 'not as an ordinary user' '! on "$srv" "su -s /bin/sh nobody -c \"/usr/local/sbin/site-lockdown status\"" 2> /dev/null'

echo; echo "######## on"
on "$srv" 'site-lockdown on --reason "CVE-2026-0001 test"' > $t/on.txt 2>&1
cat $t/on.txt
check 'web ports blocked from outside' 'blocked "$c1" 80 && blocked "$c2" 80'
((nat)) && check 'a port published through address translation is blocked too' 'blocked "$c1" 443'
check 'MySQL, other ports and SSH still reachable' 'reach "$c1" 3306 3306 && reach "$c1" 8080 8080 && [[ $(probe "$c1" 22) == SSH-* ]]'
check 'the server still reaches its own sites' 'on "$srv" "timeout 3 bash -c \"exec 3<>/dev/tcp/127.0.0.1/80 && head -1 <&3\"" | grep -qx "port 80" && on "$srv" "timeout 3 bash -c \"exec 3<>/dev/tcp/$sip/80 && head -1 <&3\"" | grep -qx "port 80"'
check 'status says who, when, why and what' 'grep -qx "lockdown: on" $t/on.txt && grep -q "^since .*, turned on by root$" $t/on.txt && grep -qx "reason: CVE-2026-0001 test" $t/on.txt && grep -q "^blocked: TCP 80, 443; UDP 80, 443 (MySQL not included)$" $t/on.txt'
check 'no systemd here, said plainly' 'grep -q "^no systemd here" $t/on.txt'
check 'logged, and to syslog' 'on "$srv" "grep -q \"  on by root: CVE-2026-0001 test\" /var/log/site-lockdown.log && grep -q \"site-lockdown -- on by root\" /var/log/test-syslog"'
check 'dropped packets counted' '[[ $(on "$srv" "site-lockdown status" | sed -n "s/^packets dropped so far: //p") -gt 0 ]]'

on "$srv" 'site-lockdown on --mysql' > /dev/null 2>&1
check '--mysql adds MySQL' 'blocked "$c1" 3306 && on "$srv" "site-lockdown status" | grep -q "(MySQL included)"'
check 'the first reason and time are kept' 'on "$srv" "site-lockdown status" | grep -qx "reason: CVE-2026-0001 test" && on "$srv" "grep -c \"  refreshed by root, MySQL added\" /var/log/site-lockdown.log" | grep -qx 1'

on "$srv" "echo 'allow = $ip2' >> /etc/site-lockdown.conf; site-lockdown on" > /dev/null 2>&1
check 'an allowed address gets through, others still do not' 'reach "$c2" 80 80 && reach "$c2" 3306 3306 && blocked "$c1" 80'
on "$srv" "echo 'allow = 999.1.1.1' >> /etc/site-lockdown.conf"
check 'a bad address in the config is refused, the block stays' '! on "$srv" "site-lockdown on" 2> /dev/null && blocked "$c1" 80 && reach "$c2" 80 80'
on "$srv" "sed -i '/999.1.1.1/d' /etc/site-lockdown.conf"

echo; echo "######## enforce"
on "$srv" 'nft delete table inet site_lockdown'
check 'with the table gone, status says so' 'on "$srv" "site-lockdown status" | grep -q "^lockdown: on, but its rules are missing" && reach "$c1" 80 80'
on "$srv" 'site-lockdown enforce' > /dev/null
check 'enforce puts it back' 'blocked "$c1" 80 && reach "$c2" 80 80 && on "$srv" "grep -q \"restored the block\" /var/log/site-lockdown.log"'
on "$srv" 'nft flush ruleset; site-lockdown enforce' > /dev/null
check 'also after nft flush ruleset' 'blocked "$c1" 80'
check 'enforce does nothing while the block is in place' '[[ -z $(on "$srv" "site-lockdown enforce") ]]'

echo; echo "######## fleet-agent over SSH"
on "$c1" 'ssh-keygen -q -t ed25519 -N "" -f /root/ctl'
on "$c1" 'cat /root/ctl' | $rt exec -i "$c2" bash -c 'cat > /root/ctl; chmod 600 /root/ctl'
key=$(on "$c1" 'cat /root/ctl.pub')
on "$srv" "cd /s && bash setup.sh controller add ctl1 --from $ip1 --key '$key'" > $t/ctl.txt 2>&1
cat $t/ctl.txt
keys=$(on "$srv" 'cat /home/fleet/.ssh/authorized_keys')
check 'controller add: key limited to fleet-agent from the control host' \
    'grep -qxE "restrict,from=\"$ip1\",command=\"/usr/local/sbin/fleet-agent --controller ctl1\" ssh-ed25519 [A-Za-z0-9+/=]+ fleet:ctl1" <<< "$keys"'
check 'the keys are root'\''s, not the fleet user'\''s' '[[ $(on "$srv" "stat -c %U:%a /home/fleet/.ssh /home/fleet/.ssh/authorized_keys" | paste -sd" ") == "root:755 root:644" ]]'
check 'sudo rule in place and valid' 'on "$srv" "visudo -cf /etc/sudoers.d/fleet-agent" > /dev/null'
check 'controller list' '[[ $(on "$srv" "cd /s && bash setup.sh controller list") == "ctl1  from $ip1  (ssh-ed25519)" ]]'
out=$(fleet "$c1" ping)
version=$(sed -n "s/^our \$VERSION = '\(.*\)';/\1/p" fleet-agent.pl)
check 'ping' 'grep -q "^fleet-agent $version on " <<< "$out" && grep -q "^php-site-watch $version$" <<< "$out"'
out=$(fleet "$c1" report)
check 'report: php-site-watch --last' 'grep -q "^== Recent runs" <<< "$out"'
out=$(fleet "$c1" packages)
check 'packages: installed and security updates' 'grep -qx "== installed packages" <<< "$out" && grep -qE "^(ii +)?perl" <<< "$out" && grep -q "^== security updates waiting" <<< "$out"'
out=$(fleet "$c1" lockdown status)
check 'lockdown status through SSH while the block is on' 'grep -qx "lockdown: on" <<< "$out"'
for bad in 'lockdown off' 'bash' 'report; id' 'report --help' 'sh -c id' 'lockdown on $(id)' 'lockdown on x;id' \
           '../../bin/sh' 'packages extra' ''; do
    out=$(fleet "$c1" "'$bad'")
    check "refused: '$bad'" 'grep -qE "^fleet-agent: (not allowed|the reason may only)" <<< "$out" && ! grep -qE "uid=|lockdown: off" <<< "$out"'
done
check 'refusals are logged' 'on "$srv" "grep -q \"fleet-agent -- controller ctl1 from $ip1 refused: lockdown off\" /var/log/test-syslog"'
check 'still on after all that' 'on "$srv" "site-lockdown status" | grep -qx "lockdown: on"'
out=$(on "$c1" "timeout 10 ssh -i /root/ctl -o BatchMode=yes -o StrictHostKeyChecking=no -W 127.0.0.1:80 fleet@$sip < /dev/null" 2>&1)
check 'no port forwarding' '! grep -q "port 80" <<< "$out"'
check 'the same key from another address is refused' '! fleet "$c2" ping | grep -q "^fleet-agent"'
check 'the fleet user cannot use sudo for anything else' '! on "$srv" "su -s /bin/sh fleet -c \"sudo -n /usr/local/sbin/site-lockdown off\"" > /dev/null 2>&1'
check 'nor turn the block off through sudo for fleet-agent' '! on "$srv" "su -s /bin/sh fleet -c \"sudo -n /usr/local/sbin/fleet-agent --root --controller x --from 1.2.3.4 lockdown-off\"" > /dev/null 2>&1 && on "$srv" "site-lockdown status" | grep -qx "lockdown: on"'

echo; echo "######## off, and a control host turning it on"
on "$srv" 'site-lockdown off' > /dev/null
check 'off: everything reachable again, state gone' 'reach "$c1" 80 80 && reach "$c1" 3306 3306 && on "$srv" "[[ ! -e /var/lib/site-lockdown/state ]]" && [[ $(on "$srv" "site-lockdown status") == "lockdown: off" ]]'
out=$(fleet "$c1" lockdown on --mysql CVE-2026-0002 seen in the wild)
echo "$out"
check 'a control host turns it on, with MySQL, and is named' 'grep -qx "lockdown: on" <<< "$out" && grep -q "turned on by controller ctl1 from $ip1$" <<< "$out" && grep -qx "reason: CVE-2026-0002 seen in the wild" <<< "$out" && blocked "$c1" 80 && blocked "$c1" 3306'
check 'its SSH still works' 'fleet "$c1" lockdown status | grep -qx "lockdown: on"'

echo; echo "######## php-site-watch health"
out=$(on "$srv" 'php-site-watch --user nobody --scan /nonexistent' 2>&1)
check 'lockdown flagged in health' 'grep -q "^!! LOCKDOWN on, since .*, turned on by controller ctl1 from $ip1; reason: CVE-2026-0002 seen in the wild$" <<< "$out"'
check 'control hosts listed' 'grep -qx "fleet control hosts: ctl1 (from $ip1)" <<< "$out"'
on "$srv" "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl intruder' >> /home/fleet/.ssh/authorized_keys"
out=$(on "$srv" 'php-site-watch --user nobody --scan /nonexistent' 2>&1)
check 'a key without the fleet-agent limit is flagged' 'grep -q "^!! 1 key(s) in /home/fleet/.ssh/authorized_keys are not limited to fleet-agent$" <<< "$out"'
on "$srv" "sed -i '/ intruder\$/d' /home/fleet/.ssh/authorized_keys"

echo; echo "######## uninstall and removing the control host"
on "$srv" 'cd /s && bash setup.sh uninstall' > $t/un.txt 2>&1; rc=$?
check 'uninstall refuses while the block is on' '((rc == 1)) && grep -q "site-lockdown is on; turn it off first" $t/un.txt && on "$srv" "[[ -x /usr/local/sbin/site-lockdown ]]"'
on "$srv" 'site-lockdown off' > /dev/null
on "$srv" 'cd /s && bash setup.sh controller remove ctl1' > /dev/null
check 'controller remove: key and sudo rule gone' '! fleet "$c1" ping | grep -q "^fleet-agent" && on "$srv" "[[ ! -e /etc/sudoers.d/fleet-agent ]]"'
on "$srv" 'cd /s && bash setup.sh uninstall --purge' > $t/un.txt 2>&1; rc=$?
check 'uninstall --purge removes it all, and the fleet user' '((rc == 0)) && on "$srv" "[[ ! -e /usr/local/sbin/site-lockdown && ! -e /usr/local/sbin/fleet-agent && ! -e /etc/site-lockdown.conf && ! -e /var/lib/site-lockdown ]] && ! getent passwd fleet"'

echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all lockdown tests passed'
exit $fail
