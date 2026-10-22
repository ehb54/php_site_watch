#!/bin/bash
# Real Apache + php-fpm 7.4 and postfix on Rocky 8: cause an out-of-memory error, crashed workers
# and a FastCGI failure for real, check that php-site-watch reports them from the actual logs,
# that it notices a php-fpm without the PHP2Shell fix and one still running a replaced binary,
# and that --status and --alert mail is delivered by postfix. From the repository directory:
#   podman run --rm -q -v "$PWD/test:/t:ro,z" -v "$PWD:/s:ro,z" quay.io/rockylinux/rockylinux:8 bash /t/test-el8-live.sh
set -u
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }

# use Rocky's main server rather than a mirror that may lag behind the latest fixes
sed -i -e 's/^mirrorlist=/#mirrorlist=/' -e 's/^#baseurl=/baseurl=/' /etc/yum.repos.d/Rocky-*.repo
dnf -y -q module enable php:7.4 > /dev/null 2>&1 || exit 9
# start from the last build without the PHP2Shell fix, to update it later
old=$(dnf -q --showduplicates list php-fpm 2> /dev/null | awk '$2 ~ /^7\.4\.33-6\./ {print $2; exit}')
[[ -n $old ]] || { echo "php-fpm 7.4.33-6 not found in the repository"; exit 9; }
dnf -y -q install httpd "php-fpm-$old" "php-common-$old" perl-interpreter procps-ng iproute findutils gzip postfix > /dev/null 2>&1 || exit 9
rpm -q php-fpm httpd perl-interpreter postfix

postconf -e 'myhostname = el8test.example.org' 'inet_interfaces = loopback-only' 'maillog_file = /var/log/maillog'
newaliases && postfix start 2> /dev/null

mkdir -p /run/php-fpm
cat > /var/www/html/oom.php <<'EOF'
<?php ini_set('memory_limit', '8M'); $a = str_repeat('x', 16 * 1024 * 1024); echo strlen($a);
EOF
echo '<?php sleep(20); echo "done";' > /var/www/html/slow.php
echo '<?php echo "home";' > /var/www/html/index.php
php-fpm -D && httpd -k start 2> /dev/null && sleep 2

curl -s -o /dev/null -w 'oom.php -> %{http_code}\n' http://localhost/oom.php
curl -s -o /dev/null -w 'POST / -> %{http_code}\n' -d a=1 http://localhost/
curl -s -o /dev/null -w 'missing.php -> %{http_code}\n' http://localhost/missing.php
curl -s -o /dev/null -w 'slow.php (workers crashed) -> %{http_code}\n' http://localhost/slow.php &
sleep 2
pkill -SEGV -u apache -f 'php-fpm: pool'    # crash every worker, including the one serving slow.php
wait
sleep 1

echo; echo "######## report on the unpatched php-fpm (account detected, default log locations)"
perl /s/php-site-watch.pl > /tmp/r1.txt; rc=$?
cat /tmp/r1.txt; echo
check 'findings: exit 1' '((rc == 1))'
check 'account and logs found' 'grep -q "PHP account apache, [1-9]" /tmp/r1.txt'
check 'crashed workers reported' 'grep -q "exited on signal 11 (SIGSEGV)" /tmp/r1.txt'
check 'real out-of-memory error reported' 'grep -q "Allowed memory size of 8388608 bytes exhausted" /tmp/r1.txt'
check 'FastCGI errors reported, scanner noise left out' 'grep -q AH01067 /tmp/r1.txt && grep -q "reset by peer" /tmp/r1.txt && ! grep -q AH01071 /tmp/r1.txt'
check 'health shows PHP 7.4.33 and the missing fix' 'grep -q "PHP: PHP 7.4.33 (/usr/sbin/php-fpm)" /tmp/r1.txt && grep -q "!! php-fpm-7.4.33-6.* lacks the PHP2Shell fix" /tmp/r1.txt'

echo; echo "######## after updating php-fpm without restarting it"
dnf -y -q update php-fpm php-common > /dev/null 2>&1
rpm -q php-fpm
perl /s/php-site-watch.pl > /tmp/r2.txt
sed -n '/== Server health/,$p' /tmp/r2.txt
check 'fix found in the updated package' 'grep -qE "PHP2Shell fix .* in php-fpm-7\.4\.33-([89]|[1-9][0-9])\..*: yes" /tmp/r2.txt'
check 'old binary still running is flagged' 'grep -q "!! php-fpm still runs a binary an update replaced; restart it" /tmp/r2.txt'

echo; echo "######## mail through postfix"
perl /s/php-site-watch.pl --status --mail-to root > /tmp/out.txt; rc=$?
check 'status mailed, nothing printed' '[[ ! -s /tmp/out.txt ]] && ((rc == 1))'
perl /s/php-site-watch.pl --alert --mail-to root
perl /s/php-site-watch.pl --alert --mail-to root    # nothing new: no second alert
sleep 5
grep '^Subject:' /var/spool/mail/root
check 'postfix delivered the status report' 'grep -qE "^Subject: \[php-site-watch\] \S+ $(date +%F): [0-9]+ findings?$" /var/spool/mail/root'
check 'postfix delivered exactly one alert' '(($(grep -c "^Subject: \[php-site-watch\] ALERT" /var/spool/mail/root) == 1))'

echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all live tests passed'
exit $fail
