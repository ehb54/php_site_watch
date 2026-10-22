#!/bin/bash
# php-site-watch on Ubuntu in a throwaway container: the PHP2Shell fix check through dpkg, with
# fixture packages whose changelog has the fix, lacks it, or is missing; plain warnings for a
# missing ps and ss; the disk line inside a container; the sockets section with and without
# CAP_SYS_PTRACE; and examples/genapp.conf. From the repository directory (works with :20.04,
# :22.04 and :24.04, and with debian:12-slim and 13-slim; run it once more with
# --cap-add SYS_PTRACE for the other half of the sockets checks):
#   podman run --rm -q -v "$PWD:/s:ro,z" docker.io/library/ubuntu:22.04 bash /s/test/test-ubuntu.sh
set -u
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
runas() { perl -e 'my @p = getpwnam(shift); $( = $p[3]; $) = "$p[3] $p[3]"; $< = $> = $p[2]; exec @ARGV or die "exec: $!"' www-data "$@"; }
psw() { perl /s/php-site-watch.pl "$@"; }
health() { psw --user www-data --scan /nonexistent "$@" | sed -n '/^== Server health/,/^$/p'; }
. /etc/os-release
echo "######## $PRETTY_NAME, perl $(perl -e 'print $^V')"
echo "dpkg excludes in this image: $(grep -h '^path-' /etc/dpkg/dpkg.cfg.d/* 2> /dev/null | paste -sd' ' -)"

echo; echo "######## 1: no ps or ss, and the disk line inside a container"
# hide ps and ss if this image has them
hidden=()
for c in ps ss; do p=$(command -v $c) && mv "$p" "$p.hidden" && hidden+=("$p"); done
psw --user www-data --scan /nonexistent > /tmp/r1.txt 2>&1
psw --scan /nonexistent > /tmp/r1b.txt 2>&1; rc=$?
for p in "${hidden[@]}"; do mv "$p.hidden" "$p"; done
cat /tmp/r1.txt; echo
check 'missing ss reported plainly' 'grep -qxF "warning: ss not found (install iproute2); sockets not checked" /tmp/r1.txt'
check 'missing ps reported plainly' 'grep -qxF "warning: ps not found (install procps); processes and sockets not checked" /tmp/r1.txt'
check 'no stray error from restoring STDERR' '! grep -qiE "illegal seek|inappropriate ioctl" /tmp/r1.txt'
check 'without ps, the PHP account has to be given' '((rc == 2)) && grep -qF "could not tell which account PHP runs as (ps not found); pass --user" /tmp/r1b.txt'
check 'files mounted from the host are not disks' 'grep -q " /etc/hosts " /proc/self/mounts && grep -q "^disk use: " /tmp/r1.txt && ! grep -qE "^(disk use|!! disk) .*/etc/(hosts|hostname|resolv\.conf)" /tmp/r1.txt'
if [[ $(df -PT / | awk 'NR == 2 {print $2}') == overlay ]]; then
    check 'the container root is shown as the host disk' 'grep -qE "^disk use: (.*, )?/ \(host disk\) [0-9]+%" /tmp/r1.txt'
fi

echo; echo "######## 2: PHP2Shell fix check through dpkg, with fixture packages"
mkdeb() {    # LABEL NAME VERSION [CHANGELOG [CONFFILE]]: build a package, print the path of the .deb
    local d=/tmp/deb/$1
    mkdir -p "$d/DEBIAN" "$d/usr/share/doc/$2"
    printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: php-site-watch tests <tests@example.org>\nDescription: php-site-watch test fixture\n' "$2" "$3" > "$d/DEBIAN/control"
    echo 'test fixture' > "$d/usr/share/doc/$2/copyright"
    [[ -n ${4:-} ]] && gzip -9nc "$4" > "$d/usr/share/doc/$2/changelog.Debian.gz"
    if [[ -n ${5:-} ]]; then
        mkdir -p "$d$(dirname "$5")" && echo '; fixture' > "$d$5" && echo "$5" > "$d/DEBIAN/conffiles"
    fi
    dpkg-deb -b "$d" "$d.deb" > /dev/null && echo "$d.deb"
}
fx=/s/test/dpkg
fixed74=$(mkdeb fixed74 php7.4-common 7.4.3-4ubuntu2.29+esm5 $fx/php7.4-fixed.changelog)
old74=$(mkdeb old74 php7.4-common 7.4.3-4ubuntu2.7 $fx/php7.4-unfixed.changelog)
nolog74=$(mkdeb nolog74 php7.4-common 7.4.3-4ubuntu2.29+esm5)
fixed81=$(mkdeb fixed81 php8.1-common 8.1.2-1ubuntu2.28 $fx/php8.1-fixed.changelog /etc/php/8.1/fixture.ini)
generic=$(mkdeb generic php-common 2:75 $fx/php7.4-unfixed.changelog)
# keep the fixtures' changelogs whatever this image leaves out of /usr/share/doc
echo 'path-include=/usr/share/doc/php*/changelog.Debian.gz' > /etc/dpkg/dpkg.cfg.d/zz-php-site-watch-test

check 'no PHP packages: no fix line' '! health | grep -q PHP2Shell'
dpkg -i "$fixed74" > /dev/null 2>&1
health > /tmp/h1.txt; cat /tmp/h1.txt
check 'fixed build: yes' 'grep -qxF "PHP2Shell fix (CVE-2026-109618/109619) in php7.4-common 7.4.3-4ubuntu2.29+esm5: yes" /tmp/h1.txt && ! grep -q "^!! php7.4" /tmp/h1.txt'

dpkg -i "$old74" > /dev/null 2>&1
health > /tmp/h2.txt; cat /tmp/h2.txt
check 'unfixed build: NO, marked !!' 'grep -qxF "PHP2Shell fix (CVE-2026-109618/109619) in php7.4-common 7.4.3-4ubuntu2.7: NO" /tmp/h2.txt && grep -qxF "!! php7.4-common 7.4.3-4ubuntu2.7 lacks the PHP2Shell fix" /tmp/h2.txt'
psw --status --user www-data --scan /nonexistent --state-dir /tmp/state --log-file none > /tmp/s2.txt
check 'unfixed build named in the status subject' 'grep -qE "^\[php-site-watch\] \S+ [0-9-]+: check (.*; )?php7\.4-common 7\.4\.3-4ubuntu2\.7 lacks the PHP2Shell fix" /tmp/s2.txt'

dpkg -i "$fixed81" "$generic" > /dev/null 2>&1
health > /tmp/h3.txt; cat /tmp/h3.txt
check 'one line per installed PHP version' 'grep -q "in php7.4-common 7.4.3-4ubuntu2.7: NO$" /tmp/h3.txt && grep -q "in php8.1-common 8.1.2-1ubuntu2.28: yes$" /tmp/h3.txt'
check 'php-common (not part of PHP itself) left out' '! grep -q "in php-common " /tmp/h3.txt'
dpkg -r php8.1-common > /dev/null 2>&1
check 'removed package with config files left: not reported' '[[ $(dpkg-query -W -f "\${Status}" php8.1-common) == "deinstall ok config-files" ]] && ! health | grep -q php8.1-common'

dpkg -i "$nolog74" > /dev/null 2>&1
health > /tmp/h4.txt; cat /tmp/h4.txt
check 'changelog missing: unknown, not flagged' 'grep -qxF "PHP2Shell fix (CVE-2026-109618/109619) in php7.4-common 7.4.3-4ubuntu2.29+esm5: unknown (no changelog)" /tmp/h4.txt && ! grep -q "^!! php7.4" /tmp/h4.txt'
rm /etc/dpkg/dpkg.cfg.d/zz-php-site-watch-test

echo; echo "######## 3: examples/genapp.conf, with ps and ss installed"
{ apt-get -q update && DEBIAN_FRONTEND=noninteractive apt-get -y -q install procps iproute2; } > /tmp/apt.log 2>&1 || { tail /tmp/apt.log; exit 9; }
mkdir -p /var/www/html/myapp/results/job1 /opt/genapp/myapp/output/html5/log /opt/genapp/myapp/bin
chown -R www-data /var/www /opt/genapp
runas touch /var/www/html/myapp/shell.php /var/www/html/myapp/results/job1/_stdout_1234 \
            /opt/genapp/myapp/output/html5/log/run.log /opt/genapp/myapp/bin/dropped /tmp/x.bin /dev/shm/y.bin

ip=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
listen='use IO::Socket::INET; my $s = IO::Socket::INET->new(LocalAddr => "0.0.0.0", LocalPort => shift, Listen => 5, ReuseAddr => 1) or die "listen: $!"; sleep 600'
perl -e "$listen" 8080 &           # root, like the web server
runas perl -e "$listen" 4444 &     # the PHP account listening: a backdoor
sleep 1
runas bash -c "exec 3<>/dev/tcp/$ip/8080; sleep 600" &
# a GenApp job: its runner, and the head its output goes through
runas perl -e '$0 = "/usr/local/bin/php /var/www/html/myapp/util/jobrun.php someone 1234 0"; sleep 600' &
runas head -c50000000 < <(sleep 600) &
runas sleep 601 &
sleep 1

psw --config /s/examples/genapp.conf > /tmp/r3.txt 2>&1; rc=$?
cat /tmp/r3.txt; echo
check 'example config read: PHP account www-data, findings' '((rc == 1)) && grep -q "PHP account www-data," /tmp/r3.txt'
check 'example: planted files found' 'grep -q /var/www/html/myapp/shell.php /tmp/r3.txt && grep -q /opt/genapp/myapp/bin/dropped /tmp/r3.txt && grep -q /tmp/x.bin /tmp/r3.txt && grep -q /dev/shm/y.bin /tmp/r3.txt'
check 'example: job results and application logs left out' '! grep -qE "results/job1|html5/log/run\.log" /tmp/r3.txt'
check 'example: GenApp job runner allowed, other processes found' 'grep -q "sleep 601" /tmp/r3.txt && ! grep -qE "jobrun\.php|head -c50000000" /tmp/r3.txt'
if (( (0x$(awk '/^CapEff/ {print $2}' /proc/self/status) >> 19) & 1 )); then
    echo "(running with CAP_SYS_PTRACE)"
    check 'sockets: listener and outbound connection found' 'grep -q "^LISTEN  0.0.0.0:4444 " /tmp/r3.txt && grep -q -- "-> $ip:8080 " /tmp/r3.txt'
    check 'sockets: no warning' '! grep -q "ss could not show" /tmp/r3.txt'
else
    echo "(running without CAP_SYS_PTRACE, as Docker containers do by default)"
    check 'sockets: warning that the PHP account'"'"'s sockets are hidden' 'grep -qxF "warning: ss could not show which processes own sockets (needs root with CAP_SYS_PTRACE), so the sockets section is incomplete" /tmp/r3.txt'
fi

psw --config /s/examples/us3lims.conf --user www-data --scan /nonexistent > /tmp/r4.txt 2>&1; rc=$?
check 'the LIMS example config reads too' '((rc <= 1)) && grep -q "PHP account www-data," /tmp/r4.txt'

echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all Ubuntu tests passed'
exit $fail
