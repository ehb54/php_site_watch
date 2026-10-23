#!/bin/bash
# Real Apache + php-fpm and postfix on Rocky 8, 9 or 10: cause an out-of-memory error, crashed
# workers and a FastCGI failure for real, check that php-site-watch reports them from the actual
# logs, that it notices a php-fpm without the PHP2Shell fix, finds the fix after an update (as a
# backport on 8 and 9, as PHP 8.3.36 itself on 10) and flags php-fpm still running the replaced
# binary, and that --status and --alert mail is delivered by postfix. From the repository directory:
#   podman run --rm -q -v "$PWD/test:/t:ro,z" -v "$PWD:/s:ro,z" quay.io/rockylinux/rockylinux:10 bash /t/test-el-live.sh
# (or :8 or :9)
set -u
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
. /etc/os-release
el=${VERSION_ID%%.*}

# use Rocky's main server rather than a mirror that may lag behind the latest fixes
sed -i -e 's/^mirrorlist=/#mirrorlist=/' -e 's/^#baseurl=/baseurl=/' /etc/yum.repos.d/[Rr]ocky*.repo
# start from the last build without the PHP2Shell fix, to update it later: Rocky 8's php:7.4 stream
# and Rocky 9's PHP 8.0 got the fix as a backport (7.4.33-8, 8.0.30-8.el9_8.1), Rocky 10 by
# following PHP's own releases (8.3.36)
case $el in
    8) dnf -y -q module enable php:7.4 > /dev/null 2>&1 || exit 9; old_re='^7\.4\.33-6\.' ;;
    9) old_re='^8\.0\.30-8\.el9_8$' ;;
    10) old_re='^8\.3\.33-' ;;
    *) echo "no test plan for Rocky $el"; exit 9 ;;
esac
old=$(dnf -q --showduplicates list php-fpm 2> /dev/null | awk -v re="$old_re" '$2 ~ re {print $2; exit}')
[[ -n $old ]] || { echo "no php-fpm matching $old_re in the repository"; exit 9; }
dnf -y -q install httpd "php-fpm-$old" "php-common-$old" perl-interpreter procps-ng iproute findutils gzip postfix > /dev/null 2>&1 || exit 9
rpm -q php-fpm httpd perl-interpreter postfix

postconf -e "myhostname = el${el}test.example.org" 'inet_interfaces = loopback-only' 'maillog_file = /var/log/maillog'
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
check "health shows PHP ${old%%-*} and the missing fix" 'grep -qF "PHP: PHP ${old%%-*} (/usr/sbin/php-fpm)" /tmp/r1.txt && grep -qF "!! php-fpm-$old" /tmp/r1.txt && grep -q " lacks the PHP2Shell fix" /tmp/r1.txt'

echo; echo "######## after updating php-fpm without restarting it"
dnf -y -q update php-fpm php-common > /dev/null 2>&1
rpm -q php-fpm
perl /s/php-site-watch.pl > /tmp/r2.txt
sed -n '/== Server health/,$p' /tmp/r2.txt
new=$(rpm -q --qf '%{VERSION}-%{RELEASE}' php-fpm)
check "fix found in the updated package $new" '[[ $new != "$old" ]] && grep -F "in php-fpm-$new" /tmp/r2.txt | grep -q ": yes"'
((el == 10)) && check 'found as a PHP release with the fix, since the changelog says only rebase' 'grep -qF ": yes (${new%%-*} is a PHP release with the fix)" /tmp/r2.txt'
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
perl /s/php-site-watch.pl --last > /tmp/last.txt
check 'run log and --last after real runs' '(($(wc -l < /var/log/php-site-watch.log) == 3)) && grep -q "  alert   .*0 new; nothing new to send$" /var/log/php-site-watch.log && grep -q "^Sent:    mailed to root$" /tmp/last.txt'

echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all live tests passed'
exit $fail
