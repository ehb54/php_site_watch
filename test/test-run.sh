#!/bin/bash
# Exercise php-site-watch.pl in a throwaway Rocky container: plant suspicious files, processes
# and sockets for a fake PHP account, run the script against the sample logs, and check the
# --status and --alert mail through a stand-in sendmail. The sample logs are dated 2026-10-22
# and 2026-10-21; they are moved to today and yesterday first.
# From the repository directory (SYS_PTRACE lets container root see socket owners, as real root can):
#   podman run --rm -q --cap-add SYS_PTRACE -v "$PWD/test:/t:ro,z" -v "$PWD:/s:ro,z" \
#       quay.io/rockylinux/rockylinux:9 bash /t/test-run.sh        (or :8)
set -u
dnf -y -q install perl-interpreter procps-ng iproute findutils gzip nmap-ncat > /dev/null 2>&1 || exit 9
# the PHP account's home is a link into /srv, as on servers that keep homes there
mkdir -p /srv/users/websvc && ln -s /srv/users/websvc /home/websvc && useradd -M -d /home/websvc websvc && chown websvc: /srv/users/websvc
runas() { perl -e 'my @p = getpwnam(shift); $( = $p[3]; $) = "$p[3] $p[3]"; $< = $> = $p[2]; exec @ARGV or die "exec: $!"' websvc "$@"; }
fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }

today=$(date +%F)
cp -r /t/logs /logs
for f in $(find /logs -type f ! -name '*.gz'); do
    sed -i -E \
        -e "s#22-Oct-2026#$(date +%d-%b-%Y)#g; s#21-Oct-2026#$(date -d yesterday +%d-%b-%Y)#g" \
        -e "s#22/Oct/2026#$(date +%d/%b/%Y)#g; s#21/Oct/2026#$(date -d yesterday +%d/%b/%Y)#g" \
        -e "s#2026/10/22#$(date +%Y/%m/%d)#g; s#2026/10/21#$(date -d yesterday +%Y/%m/%d)#g" \
        -e "s#^\[(...) Oct 22 ([0-9:.]+) 2026\]#[\1 $(date '+%b %d') \2 $(date +%Y)]#" \
        -e "s#^\[(...) Oct 21 ([0-9:.]+) 2026\]#[\1 $(date -d yesterday '+%b %d') \2 $(date -d yesterday +%Y)]#" \
        -e "s#^\[(...) Oct 22 ([0-9:.]+) 2025\]#[\1 $(date '+%b %d') \2 $(($(date +%Y) - 1))]#" "$f"
done
gz=/logs/httpd/access_log-20261023.gz
gzip -dc $gz | sed "s#22/Oct/2026#$(date +%d/%b/%Y)#g" | gzip -c > $gz.new && mv $gz.new $gz
touch -d '30 days ago' /logs/httpd/error_log-20261001    # a rotated file too old to matter

# what the web server serves and PHP uses, for the default scan; /srv/backup is neither
mkdir -p /etc/httpd/conf /etc/httpd/conf.d /etc/nginx/conf.d /etc/php-fpm.d /srv/www/htdocs/docs /srv/nginx/site \
         /srv/nginx/files /srv/uploads /srv/backup
printf 'ServerRoot "/etc/httpd"\nDocumentRoot "/srv/www/htdocs"\nIncludeOptional conf.d/*.conf\n' > /etc/httpd/conf/httpd.conf
printf 'Alias /trac "/srv/trac"\nAlias /docs /srv/www/htdocs/docs\n# Alias /old /srv/backup\n' > /etc/httpd/conf.d/apps.conf
printf 'http {\n    include conf.d/*.conf;\n}\n' > /etc/nginx/nginx.conf
printf 'server { listen 8080; root /srv/nginx/site; location /files/ { alias /srv/nginx/files/; } }\n' > /etc/nginx/conf.d/site.conf
printf '[www]\nuser = websvc\nphp_admin_value[upload_tmp_dir] = /srv/uploads\n' > /etc/php-fpm.d/www.conf
mkdir -p /srv/www/htdocs /srv/trac/proj/log /var/lib/php/session
chown -R websvc /srv /var/lib/php/session
runas touch /srv/www/htdocs/shell.php /srv/trac/proj/log/trac.log /home/websvc/.uslims_backup_stats \
            /var/lib/php/session/sess_abc123 /tmp/x.bin
runas touch /srv/nginx/site/n.php /srv/nginx/files/f.txt /srv/uploads/phpAbc123 /srv/backup/dump.php
# a whole directory the test config excludes, which the scan skips; a find that records its arguments
mkdir -p /srv/www/htdocs/cache && chown websvc /srv/www/htdocs/cache && runas touch /srv/www/htdocs/cache/c.php
printf '#!/bin/bash\necho "$*" >> /tmp/find-args\nexec /usr/bin/find "$@"\n' > /usr/local/bin/find && chmod +x /usr/local/bin/find
runas touch -d '3 days ago' /srv/www/htdocs/old.php

ip=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
runas perl -e '$0 = "php-fpm: pool www"; sleep 600' &
runas sleep 600 &
ncat -lk 0.0.0.0 8099 > /dev/null &
runas ncat -lk 0.0.0.0 4444 > /dev/null &
sleep 1
runas bash -c "exec 3<>/dev/tcp/$ip/8099; sleep 600" &
runas bash -c 'exec 3<>/dev/tcp/127.0.0.1/8099; sleep 600' &
sleep 1

logs=(--fpm-logs /logs/fpm --web-logs /logs/httpd --web-logs /logs/nginx)
echo "######## 1: full report with the test config (container IP $ip)"
perl /s/php-site-watch.pl --config /t/test.conf "${logs[@]}" > /tmp/r1.txt; rc=$?
cat /tmp/r1.txt; echo
check 'report exits 1 with findings' '((rc == 1))'
check 'crashes, out-of-memory and FastCGI errors found' 'grep -q "child 502 exited on signal 11" /tmp/r1.txt && grep -q "child 503 exited with code 255" /tmp/r1.txt && grep -q AH00052 /tmp/r1.txt && grep -q "Allowed memory size of 134217728" /tmp/r1.txt && grep -q "Maximum execution time" /tmp/r1.txt && grep -q "reached pm.max_children" /tmp/r1.txt && grep -q "AH01067: Failed to read FastCGI header" /tmp/r1.txt && grep -q "upstream prematurely closed connection while" /tmp/r1.txt'
check 'noise, other days and old rotated files left out' '! grep -qE "SIGTERM|AH01071|child 400|8\.8\.8\.8|8\.8\.4\.4|child pid 9999|previous day" /tmp/r1.txt'
check '5xx and POST counts, including the rotated .gz log' 'grep -qE "^ +2  1\.2\.3\.4 POST / 503$" /tmp/r1.txt && grep -q "9.8.7.6 POST /upload.php 502" /tmp/r1.txt && grep -qE "^ +2  9\.8\.7\.6$" /tmp/r1.txt'
check 'planted files found, expected ones left out' 'grep -q shell.php /tmp/r1.txt && grep -q /tmp/x.bin /tmp/r1.txt && ! grep -qE "trac\.log|uslims_backup_stats|sess_abc123|old\.php" /tmp/r1.txt'
check 'default scan: web roots, aliases, PHP upload dir, home; not /srv/backup' 'grep -qE "^changed files looked for in: /dev/shm, /home/websvc, /srv/nginx/files, /srv/nginx/site, /srv/trac, /srv/uploads, /srv/www/htdocs, /tmp, /var/tmp; skipped: /srv/www/htdocs/cache \([0-9]+ s\)\$" /tmp/r1.txt && grep -q /srv/nginx/site/n.php /tmp/r1.txt && grep -q /srv/nginx/files/f.txt /tmp/r1.txt && grep -q /srv/uploads/phpAbc123 /tmp/r1.txt && ! grep -q dump.php /tmp/r1.txt'
check 'a whole-directory exclude is skipped during the scan' 'grep -qF -- "( -path /srv/www/htdocs/cache ) -prune -o -type f -user websvc" /tmp/find-args && ! grep -q /srv/www/htdocs/cache/c.php /tmp/r1.txt'
check 'planted processes found, PHP worker allowed' 'grep -q "ncat -lk 0.0.0.0 4444" /tmp/r1.txt && ! grep -q "php-fpm: pool www" /tmp/r1.txt'
check 'PHP notices and warnings are not FastCGI failures' '! grep -qE "Content-type not specified|Undefined variable" /tmp/r1.txt'
check 'application fatal errors grouped for context' 'grep -qE "^ +2  Uncaught Error: Undefined constant \"d\" in /srv/www/htdocs/somo/pubs.php:79$" /tmp/r1.txt'
check 'listener and outbound connection found, loopback left out' 'grep -q "LISTEN  0.0.0.0:4444" /tmp/r1.txt && grep -q -- "-> $ip:8099" /tmp/r1.txt && ! grep -q -- "-> 127.0.0.1:8099" /tmp/r1.txt'
check 'health section present' 'grep -q "== Server health (now)" /tmp/r1.txt'

echo; echo "######## 2: --quiet, PHP account detected, no config"
perl /s/php-site-watch.pl --quiet "${logs[@]}" > /tmp/r2.txt; rc=$?
check 'account detected from the php-fpm worker' 'grep -q "PHP account websvc" /tmp/r2.txt && ((rc == 1))'
check 'quiet output leaves out context and health' '! grep -qE "== (5xx|Most active|Server health)" /tmp/r2.txt'
check 'without the config, Trac and backup files show up' 'grep -q trac.log /tmp/r2.txt && grep -q " /home/websvc/\.uslims_backup_stats\$" /tmp/r2.txt && ! grep -q /srv/users/websvc /tmp/r2.txt'

echo; echo "######## 3: mail through a stand-in sendmail"
mkdir /tmp/mail
cat > /tmp/fake-sendmail <<'EOF'
#!/bin/bash
n=$(ls /tmp/mail | wc -l)
{ echo "ARGS: $*"; cat; } > /tmp/mail/$((n + 1)).txt
EOF
chmod +x /tmp/fake-sendmail
mailopts=(--config /t/test.conf "${logs[@]}" --sendmail /tmp/fake-sendmail --state-dir /tmp/state --log-file /tmp/run.log)
perl /s/php-site-watch.pl --status --mail-to ops@example.org,second@example.org --mail-from watch@example.org "${mailopts[@]}" > /tmp/out.txt; rc=$?
check 'status is mailed, not printed' '[[ -f /tmp/mail/1.txt && ! -s /tmp/out.txt ]] && ((rc == 1))'
check 'status mail headers' 'grep -q "^ARGS: -oi -t -f watch@example.org$" /tmp/mail/1.txt && grep -q "^To: ops@example.org, second@example.org$" /tmp/mail/1.txt && grep -q "^From: watch@example.org$" /tmp/mail/1.txt && grep -qE "^Subject: \[php-site-watch\] \S+ $today: [0-9]+ findings$" /tmp/mail/1.txt'
check 'status mail has the full report and health' 'grep -q "== Server health (now)" /tmp/mail/1.txt && grep -q "== Most active POST senders" /tmp/mail/1.txt'
perl /s/php-site-watch.pl --alert --mail-to ops@example.org "${mailopts[@]}"
check 'first alert mailed, covering yesterday too' 'grep -qE "^Subject: \[php-site-watch\] ALERT \S+: [0-9]+ new findings$" /tmp/mail/2.txt && grep -q "child 400 exited on signal 11" /tmp/mail/2.txt && grep -q shell.php /tmp/mail/2.txt'
check 'alert leaves out context and health' '! grep -qE "== (5xx|Most active|Server health)" /tmp/mail/2.txt && ! grep -q "Uncaught Error" /tmp/mail/2.txt'
perl /s/php-site-watch.pl --alert --mail-to ops@example.org "${mailopts[@]}"
check 'second alert sends nothing' '[[ ! -e /tmp/mail/3.txt ]]'
runas touch /srv/www/htdocs/another.php
perl /s/php-site-watch.pl --alert --mail-to ops@example.org "${mailopts[@]}"
check 'third alert has only the new file' 'grep -q "^Subject: .*ALERT .*: 1 new finding$" /tmp/mail/3.txt && grep -q another.php /tmp/mail/3.txt && ! grep -q shell.php /tmp/mail/3.txt'
check 'run log: one line per run' '(($(wc -l < /tmp/run.log) == 4)) && grep -qE "^\S+ \S+  status  $today: [0-9]+ findings; mailed to ops@example.org, second@example.org$" /tmp/run.log && grep -qE "^\S+ \S+  alert   .*: [0-9]+ findings, 0 new; nothing new to send$" /tmp/run.log && grep -qE "^\S+ \S+  alert   .*: [0-9]+ findings, 1 new; mailed to ops@example.org$" /tmp/run.log'
check 'latest status and alert saved' 'grep -q "^Sent:    mailed to ops@example.org, second@example.org$" /tmp/state/last-status.txt && grep -q "== Server health" /tmp/state/last-status.txt && grep -q "^Subject: .*ALERT .*: 1 new finding$" /tmp/state/last-alert.txt && grep -q another.php /tmp/state/last-alert.txt'
perl /s/php-site-watch.pl --last --state-dir /tmp/state --log-file /tmp/run.log > /tmp/last.txt
check '--last shows the runs and both reports' 'grep -q "^== Recent runs" /tmp/last.txt && grep -q "^== Latest status report" /tmp/last.txt && grep -q "^== Latest alert report" /tmp/last.txt && grep -q another.php /tmp/last.txt && (($(grep -c "  alert   " /tmp/last.txt) == 3))'
perl /s/php-site-watch.pl --status --config /t/test.conf "${logs[@]}" --mail-to ops@example.org --sendmail /nonexistent/sendmail --state-dir /tmp/state --log-file /tmp/run.log 2> /dev/null; rc=$?
check 'a mail failure is logged' '((rc == 2)) && grep -qE "  status  error: cannot run /nonexistent/sendmail" /tmp/run.log'
cp /t/test.conf /tmp/mail.conf
printf 'mail-to = cfg1@example.org\nmail-to = cfg2@example.org, cfg3@example.org\n' >> /tmp/mail.conf
cfgopts=("${logs[@]}" --sendmail /tmp/fake-sendmail --state-dir /tmp/state --log-file /tmp/run.log)
perl /s/php-site-watch.pl --status --config /tmp/mail.conf "${cfgopts[@]}"
check 'recipients come from the config' 'grep -q "^To: cfg1@example.org, cfg2@example.org, cfg3@example.org$" /tmp/mail/4.txt'
perl /s/php-site-watch.pl --status --config /tmp/mail.conf --mail-to only@example.org "${cfgopts[@]}"
check '--mail-to replaces the config recipients' 'grep -q "^To: only@example.org$" /tmp/mail/5.txt'
perl /s/php-site-watch.pl --alert --mail-to 'x@y; rm -rf /' "${mailopts[@]}" 2> /dev/null; rc=$?
check 'malformed --mail-to rejected' '((rc == 2))'
perl /s/php-site-watch.pl --alert --date "$today" "${mailopts[@]}" 2> /dev/null; rc=$?
check '--alert with --date rejected' '((rc == 2))'

echo; echo "######## lock: scheduled runs take turns"
hold() { perl -e 'open my $f, ">>", "/tmp/state/lock" or die; flock $f, 2 or die; sleep shift' "$1" & holder=$!; sleep 1; }
hold 3; n=$(ls /tmp/mail | wc -l)
perl /s/php-site-watch.pl --alert "${mailopts[@]}" > /tmp/out.txt; rc=$?
check 'an alert skips the hour while another run holds the lock' '((rc == 0)) && [[ ! -s /tmp/out.txt ]] && (($(ls /tmp/mail | wc -l) == n)) && tail -1 /tmp/run.log | grep -qE "  alert   skipped: the previous run is still going\$"'
wait $holder
hold 3; start=$(date +%s)
perl /s/php-site-watch.pl --status --mail-to ops@example.org "${mailopts[@]}" > /dev/null
check 'the status waits for its turn, then runs' '(($(date +%s) - start >= 2)) && tail -1 /tmp/run.log | grep -qE "  status  \S+: .*; mailed to ops@example.org\$"'
wait $holder

echo; echo "######## 4: --quiet on a clean day after removing the planted files and processes"
{ pkill -u websvc; kill $(jobs -p); wait; } 2> /dev/null    # every helper, including the root ncat listener
rm -f /srv/www/htdocs/shell.php /srv/www/htdocs/another.php /tmp/x.bin /srv/nginx/site/n.php /srv/nginx/files/f.txt /srv/uploads/phpAbc123
perl /s/php-site-watch.pl --quiet --config /t/test.conf --date "$(date -d '3 days ago' +%F)" "${logs[@]}" > /tmp/r4.txt; rc=$?
check 'clean day: no output, exit 0' '[[ ! -s /tmp/r4.txt ]] && ((rc == 0))' || cat /tmp/r4.txt

echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all tests passed'
exit $fail
