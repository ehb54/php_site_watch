#!/bin/bash
# Real Apache with mod_php on Ubuntu in a throwaway container: crashed workers and an out-of-memory
# error from the actual logs, the PHP2Shell check on the archive's own packages, and a PHP update
# that replaces the module while Apache keeps running the old one: in containers, package updates
# don't restart services, and a graceful restart keeps the old module too; only a stop and start
# loads the new one. From the repository directory (with :20.04, :22.04 or :24.04):
#   podman run --rm -q -v "$PWD:/s:ro,z" docker.io/library/ubuntu:22.04 bash /s/test/test-ubuntu-live.sh
set -u
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
psw() { perl /s/php-site-watch.pl; }
get() {    # PATH [BODY]: one request to the local Apache, a POST if there is a body; prints the status
    local status
    exec 3<> /dev/tcp/127.0.0.1/80 || return 1
    if (($# > 1)); then
        printf 'POST %s HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s' "$1" "${#2}" "$2" >&3
    else
        printf 'GET %s HTTP/1.0\r\nHost: localhost\r\n\r\n' "$1" >&3
    fi
    { read -r _ status _; cat > /dev/null; } <&3
    exec 3<&-
    echo "$status"
}
. /etc/os-release
case $VERSION_ID in
    20.04) v=7.4 fixed=NO ;;    # the 20.04 fix is in Ubuntu Pro only
    22.04) v=8.1 fixed=yes ;;
    24.04) v=8.3 fixed=yes ;;
    *) echo "no PHP version known for $PRETTY_NAME"; exit 9 ;;
esac
echo "######## $PRETTY_NAME, PHP $v"
[[ -e /usr/sbin/policy-rc.d ]] && echo "this image has /usr/sbin/policy-rc.d" || echo "this image has no /usr/sbin/policy-rc.d"
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d    # as in containers: packages may not start or restart services
chmod 755 /usr/sbin/policy-rc.d

# the oldest PHP build of this release, to update it later
export DEBIAN_FRONTEND=noninteractive
apt-get -q update > /tmp/apt.log 2>&1 || { tail /tmp/apt.log; exit 9; }
old=$(apt-cache madison "libapache2-mod-php$v" | awk '{print $3}' | tail -1)
new=$(apt-cache madison "libapache2-mod-php$v" | awk '{print $3}' | head -1)
[[ -n $old && $old != "$new" ]] || { echo "no older build of PHP $v to update from"; exit 9; }
pkgs=$(apt-get -s install --no-install-recommends "libapache2-mod-php$v" \
           | awk -v v="$v" '$1 == "Inst" && ($2 ~ "^php" v "-" || $2 == "libapache2-mod-php" v) {print $2}')
old_pkgs=() new_pkgs=()
for p in $pkgs; do old_pkgs+=("$p=$old") new_pkgs+=("$p=$new"); done
apt-get -y -q install --no-install-recommends apache2 procps iproute2 "${old_pkgs[@]}" >> /tmp/apt.log 2>&1 \
    || { tail /tmp/apt.log; exit 9; }
dpkg-query -W -f '${Package} ${Version}\n' $pkgs

cat > /var/www/html/oom.php <<'EOF'
<?php ini_set('memory_limit', '8M'); $a = str_repeat('x', 16 * 1024 * 1024); echo strlen($a);
EOF
echo '<?php echo "home";' > /var/www/html/index.php
# which PHP module the Apache process serving a request runs: the one an update replaced, or the current one
cat > /var/www/html/module.php <<'EOF'
<?php $m = file_get_contents('/proc/self/maps');
$old = preg_match('/libphp\S*\.so \(deleted\)$/m', $m); $current = preg_match('/libphp\S*\.so$/m', $m);
echo $old && !$current ? 'old' : ($current && !$old ? 'current' : 'unclear');
EOF
served() { local b; exec 3<> /dev/tcp/127.0.0.1/80; printf 'GET /module.php HTTP/1.0\r\n\r\n' >&3; b=$(cat <&3); exec 3<&-; echo "${b##*$'\n'}"; }
apache2ctl start 2> /dev/null
sleep 2
echo "PHP module serving requests: $(served)"
echo "GET /oom.php -> $(get /oom.php)"
echo "POST /index.php -> $(get /index.php a=1)"
pkill -SEGV -u www-data -x apache2    # crash every worker
sleep 2

echo; echo "######## report on the old build (account detected, default log locations)"
psw > /tmp/r1.txt; rc=$?
cat /tmp/r1.txt; echo
check 'findings: exit 1' '((rc == 1))'
check 'account detected from the Apache workers, logs found' 'grep -q "PHP account www-data, [1-9]" /tmp/r1.txt'
check 'crashed workers reported' 'grep -q "AH00052: child pid [0-9]* exit signal Segmentation fault" /tmp/r1.txt'
check 'real out-of-memory error reported' 'grep -q "Allowed memory size of 8388608 bytes exhausted" /tmp/r1.txt'
check '500 response and POST sender counted' 'grep -qE "^ +1  127\.0\.0\.1 GET /oom\.php 500$" /tmp/r1.txt && grep -qE "^ +1  127\.0\.0\.1$" /tmp/r1.txt'
check 'old build: no fix' 'grep -qxF "PHP2Shell fix (CVE-2026-109618/109619) in php$v-common $old: NO" /tmp/r1.txt'
check 'Apache runs the installed module: nothing flagged' '! grep -q "still runs a PHP module" /tmp/r1.txt && [[ $(served) == current ]]'

echo; echo "######## after updating PHP while Apache keeps running"
apt-get -y -q install --no-install-recommends "${new_pkgs[@]}" >> /tmp/apt.log 2>&1 \
    || { tail /tmp/apt.log; exit 9; }
grep -h 'policy-rc.d denied' /tmp/apt.log | sort -u
psw > /tmp/r2.txt
sed -n '/== Server health/,$p' /tmp/r2.txt
stale='!! apache2 still runs a PHP module an update replaced; stop and start it (a graceful restart keeps the old one)'
check "updated build: fix $fixed" 'grep -qxF "PHP2Shell fix (CVE-2026-109618/109619) in php$v-common $new: $fixed" /tmp/r2.txt'
check 'Apache still running the replaced module is flagged' 'grep -qxF "$stale" /tmp/r2.txt && [[ $(served) == old ]]'

apache2ctl graceful 2> /dev/null
sleep 3
psw > /tmp/r3.txt
echo "PHP module serving requests after a graceful restart: $(served)"
check 'a graceful restart keeps the old module: still flagged' 'grep -qxF "$stale" /tmp/r3.txt && [[ $(served) == old ]]'

master=$(cat /var/run/apache2/apache2.pid)
service apache2 restart > /dev/null 2>&1    # stops and starts it
sleep 2
psw > /tmp/r4.txt
echo "PHP module serving requests after service apache2 restart: $(served) (Apache master $master -> $(cat /var/run/apache2/apache2.pid))"
check 'after a stop and start: the update serves, nothing flagged' '! grep -q "still runs a PHP module" /tmp/r4.txt && [[ $(served) == current ]]'

echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all Ubuntu live tests passed'
exit $fail
