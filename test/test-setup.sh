#!/bin/bash
# Exercise setup.sh install / mail / uninstall in a throwaway Rocky container. From the repository directory:
#   podman run --rm -q -v "$PWD:/s:ro,z" quay.io/rockylinux/rockylinux:9 bash /s/test/test-setup.sh   (or :8)
set -u
dnf -y -q install perl-interpreter procps-ng iproute findutils > /dev/null 2>&1 || exit 9
cp -r /s /repo && cd /repo
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
c=/etc/cron.d/php-site-watch
conf=/etc/php-site-watch.conf

./setup.sh install
check 'script installed and runs' '[[ -x /usr/local/sbin/php-site-watch ]] && php-site-watch --version | grep -q "^php-site-watch "'
check 'commented config installed' '[[ -f $conf ]] && ! grep -qv "^\s*\(#\|$\)" $conf'
check 'no cron job without --cron' '[[ ! -e $c ]]'
php-site-watch --user nobody --scan /nonexistent > /tmp/run.txt; rc=$?
check 'runs with the installed config (exit 0 or 1)' '((rc <= 1)) && grep -q "^php-site-watch " /tmp/run.txt'

./setup.sh install --cron > /tmp/nocron.txt 2>&1; rc=$?
check '--cron without cron installed fails clearly' '((rc == 1)) && grep -q "install cron first" /tmp/nocron.txt'
dnf -y -q install cronie > /dev/null 2>&1
./setup.sh install --cron --mailto 'x@y; reboot' > /dev/null 2>&1; rc=$?
check 'malformed --mailto rejected' '((rc == 1)) && [[ ! -e $c ]]'

# settings for running the jobs here: a stand-in sendmail and nothing to scan
mkdir /tmp/mail
cat > /tmp/fake-sendmail <<'EOF'
#!/bin/bash
n=$(ls /tmp/mail | wc -l)
{ echo "ARGS: $*"; cat; } > /tmp/mail/$((n + 1)).txt
EOF
chmod +x /tmp/fake-sendmail
printf 'user = nobody\nscan = /nonexistent\nsendmail = /tmp/fake-sendmail\nstate-dir = /tmp/state\n' >> $conf

./setup.sh install --cron --mailto 'ops@example.org, second@example.org' --mailfrom watch@example.org > /tmp/inst.txt
cat $c
check 'existing config kept' 'grep -q "^user = nobody" $conf'
check 'recipients and sender stored in the config' 'grep -q "^mail-to = ops@example.org$" $conf && grep -q "^mail-to = second@example.org$" $conf && grep -q "^mail-from = watch@example.org$" $conf'
check 'cron jobs written without addresses' 'grep -q "^PATH=/usr/local/sbin:" $c && grep -q "^5 \* \* \* \* root /usr/local/sbin/php-site-watch --alert$" $c && grep -q "^0 7 \* \* \* root /usr/local/sbin/php-site-watch --status --date yesterday$" $c'
check 'cron error mail goes to the recipients' 'grep -q "^MAILTO=ops@example.org,second@example.org$" $c'
check 'install says where reports go' 'grep -q "reports go to: ops@example.org, second@example.org" /tmp/inst.txt'

./setup.sh mail list > /tmp/list.txt
check 'mail list' '[[ $(cat /tmp/list.txt) == $'"'"'ops@example.org\nsecond@example.org'"'"' ]]'
./setup.sh mail add third@example.org OPS@example.org > /tmp/add.txt
check 'mail add, ignoring one already there' 'grep -q "added third@example.org" /tmp/add.txt && grep -q "OPS@example.org already gets the reports" /tmp/add.txt && (($(./setup.sh mail list | wc -l) == 3))'
check 'cron error mail follows' 'grep -q "^MAILTO=ops@example.org,second@example.org,third@example.org$" $c'
./setup.sh mail remove second@example.org nobody@example.org > /tmp/rm.txt
check 'mail remove' 'grep -q "removed second@example.org" /tmp/rm.txt && grep -q "nobody@example.org does not get the reports" /tmp/rm.txt && ! grep -q second@example.org $conf && grep -q "^MAILTO=ops@example.org,third@example.org$" $c'
echo 'mail-to = a@example.org, b@example.org' >> $conf
./setup.sh mail remove a@example.org > /dev/null
check 'mail remove from a comma-separated line' 'grep -q "^mail-to = b@example.org$" $conf'
./setup.sh mail add 'bad address' > /dev/null 2>&1; rc=$?
check 'mail add rejects a malformed address' '((rc == 1))'

./setup.sh mail test > /tmp/test.txt; rc=$?
check 'mail test reports where it went' '((rc == 0)) && grep -q "status report mailed to: ops@example.org, third@example.org, b@example.org" /tmp/test.txt'
check 'mail test mailed every recipient' 'grep -q "^To: ops@example.org, third@example.org, b@example.org$" /tmp/mail/1.txt && grep -q "^From: watch@example.org$" /tmp/mail/1.txt'
./setup.sh mail from none > /dev/null
check 'mail from none clears the sender' '! grep -q "^mail-from" $conf'

# run both jobs as cron would (sh, cron's short PATH)
sed -n 's/^[0-9*]* [0-9*]* \* \* \* root //p' $c > /tmp/jobs.txt
check 'two jobs found' '(($(wc -l < /tmp/jobs.txt) == 2))'
while read -r job; do
    env -i PATH=/usr/bin:/bin sh -c "$job"; rc=$?
    check "job runs under sh: $job" '((rc <= 1))'
done < /tmp/jobs.txt
check 'status job mailed a report' 'grep -l "^Subject: \[php-site-watch\] .* $(date -d yesterday +%F): " /tmp/mail/*.txt > /dev/null'

./setup.sh mail remove ops@example.org third@example.org b@example.org > /dev/null
check 'no recipients: cron mails root' '[[ -z $(./setup.sh mail list | grep @) ]] && grep -q "^MAILTO=root$" $c'
./setup.sh mail test > /dev/null 2>&1; rc=$?
check 'mail test without recipients fails clearly' '((rc == 1))'

# an install from before 1.4.0 kept the addresses on the cron jobs; update moves them into the config
cat > $c <<'EOF'
# php-site-watch (installed by setup.sh)
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=old1@example.org,old2@example.org
5 * * * * root /usr/local/sbin/php-site-watch --alert --mail-to old1@example.org,old2@example.org --mail-from oldfrom@example.org
30 6 * * * root /usr/local/sbin/php-site-watch --status --date yesterday --mail-to old1@example.org,old2@example.org --mail-from oldfrom@example.org
EOF
./setup.sh install > /tmp/migrate.txt
cat $c
check 'old cron addresses moved into the config' 'grep -q "moved the report addresses" /tmp/migrate.txt && grep -q "^mail-to = old1@example.org$" $conf && grep -q "^mail-to = old2@example.org$" $conf && grep -q "^mail-from = oldfrom@example.org$" $conf'
check 'old cron jobs keep their schedule, lose the addresses' 'grep -q "^5 \* \* \* \* root /usr/local/sbin/php-site-watch --alert$" $c && grep -q "^30 6 \* \* \* root /usr/local/sbin/php-site-watch --status --date yesterday$" $c && grep -q "^MAILTO=old1@example.org,old2@example.org$" $c'

# the real installs had --mail-to only, no --mail-from
./setup.sh mail remove old1@example.org old2@example.org > /dev/null
./setup.sh mail from none > /dev/null
cat > $c <<'EOF'
# php-site-watch (installed by setup.sh)
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=only@example.org
5 * * * * root /usr/local/sbin/php-site-watch --alert --mail-to only@example.org
0 7 * * * root /usr/local/sbin/php-site-watch --status --date yesterday --mail-to only@example.org
EOF
./setup.sh install > /tmp/migrate2.txt; rc=$?
cat /tmp/migrate2.txt
check 'migration works without --mail-from' '((rc == 0)) && grep -q "^mail-to = only@example.org$" $conf && ! grep -q "^mail-from" $conf && ! grep -q -- "--mail-to" $c && grep -q "reports go to: only@example.org" /tmp/migrate2.txt'

./setup.sh install > /tmp/again.txt
check 'reinstall without --cron keeps the cron job' 'grep -q "kept $c" /tmp/again.txt && [[ -e $c ]]'

mkdir -p /var/lib/php-site-watch
./setup.sh uninstall
check 'uninstall removes script and cron job' '[[ ! -e /usr/local/sbin/php-site-watch && ! -e $c ]]'
check 'uninstall keeps the config and alert history' '[[ -e $conf && -d /var/lib/php-site-watch ]]'
./setup.sh uninstall --purge
check 'uninstall --purge removes config and alert history' '[[ ! -e $conf && ! -e /var/lib/php-site-watch ]]'

./setup.sh bogus > /dev/null 2>&1; rc=$?
check 'unknown command shows usage and fails' '((rc == 1))'
echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all setup tests passed'
exit $fail
