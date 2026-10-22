#!/bin/bash
# Exercise setup.sh install / uninstall in a throwaway Rocky container. From the repository directory:
#   podman run --rm -q -v "$PWD:/s:ro,z" quay.io/rockylinux/rockylinux:9 bash /s/test/test-setup.sh   (or :8)
set -u
dnf -y -q install perl-interpreter procps-ng iproute findutils > /dev/null 2>&1 || exit 9
cp -r /s /repo && cd /repo
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
c=/etc/cron.d/php-site-watch

./setup.sh install
check 'script installed and runs' '[[ -x /usr/local/sbin/php-site-watch ]] && php-site-watch --version | grep -q "^php-site-watch "'
check 'commented config installed' '[[ -f /etc/php-site-watch.conf ]] && ! grep -qv "^\s*\(#\|$\)" /etc/php-site-watch.conf'
check 'no cron job without --cron' '[[ ! -e $c ]]'
php-site-watch --user nobody --scan /nonexistent > /tmp/run.txt; rc=$?
check 'runs with the installed config (exit 0 or 1)' '((rc <= 1)) && grep -q "^php-site-watch " /tmp/run.txt'

./setup.sh install --cron > /tmp/nocron.txt 2>&1; rc=$?
check '--cron without cron installed fails clearly' '((rc == 1)) && grep -q "install cron first" /tmp/nocron.txt'
dnf -y -q install cronie > /dev/null 2>&1
./setup.sh install --cron --mailto 'x@y; reboot' > /dev/null 2>&1; rc=$?
check 'malformed --mailto rejected' '((rc == 1)) && [[ ! -e $c ]]'

echo 'user = nobody' >> /etc/php-site-watch.conf
./setup.sh install --cron --mailto 'ops@example.org, second@example.org' --mailfrom watch@example.org
cat $c
check 'existing config kept' 'grep -q "^user = nobody" /etc/php-site-watch.conf'
check 'cron jobs written' 'grep -q "^PATH=/usr/local/sbin:" $c && grep -q "^MAILTO=ops@example.org,second@example.org$" $c && grep -q "^5 \* \* \* \* root /usr/local/sbin/php-site-watch --alert --mail-to ops@example.org,second@example.org --mail-from watch@example.org$" $c && grep -q "^0 7 \* \* \* root /usr/local/sbin/php-site-watch --status --date yesterday --mail-to ops@example.org,second@example.org --mail-from watch@example.org$" $c'

# run both jobs as cron would (sh, cron's short PATH), mailing through a stand-in sendmail
mkdir /tmp/mail
cat > /tmp/fake-sendmail <<'EOF'
#!/bin/bash
n=$(ls /tmp/mail | wc -l)
{ echo "ARGS: $*"; cat; } > /tmp/mail/$((n + 1)).txt
EOF
chmod +x /tmp/fake-sendmail
sed -n 's/^[0-9*]* [0-9*]* \* \* \* root //p' $c > /tmp/jobs.txt
check 'two jobs found' '(($(wc -l < /tmp/jobs.txt) == 2))'
while read -r job; do
    env -i PATH=/usr/bin:/bin sh -c "$job --scan /nonexistent --sendmail /tmp/fake-sendmail --state-dir /tmp/state"; rc=$?
    check "job runs under sh: ${job%% --mail-to*}" '((rc <= 1))'
done < /tmp/jobs.txt
check 'status job mailed a report' 'grep -l "^Subject: \[php-site-watch\] .* $(date -d yesterday +%F): " /tmp/mail/*.txt > /dev/null'

./setup.sh install > /tmp/again.txt
check 'reinstall without --cron keeps the cron job' 'grep -q "kept $c" /tmp/again.txt && [[ -e $c ]]'

mkdir -p /var/lib/php-site-watch
./setup.sh uninstall
check 'uninstall removes script and cron job' '[[ ! -e /usr/local/sbin/php-site-watch && ! -e $c ]]'
check 'uninstall keeps the config and alert history' '[[ -e /etc/php-site-watch.conf && -d /var/lib/php-site-watch ]]'
./setup.sh uninstall --purge
check 'uninstall --purge removes config and alert history' '[[ ! -e /etc/php-site-watch.conf && ! -e /var/lib/php-site-watch ]]'

./setup.sh bogus > /dev/null 2>&1; rc=$?
check 'unknown command shows usage and fails' '((rc == 1))'
echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all setup tests passed'
exit $fail
