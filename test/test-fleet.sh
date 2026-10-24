#!/bin/bash
# fleet.pl in throwaway containers on a network of their own: a person's machine (adm) and two
# servers with sshd and sudo, one with Apache (s1) and one with nginx (s2). It checks the inventory
# checks; add's refusals (no profile, no sudo, nobody to ask, a broken inventory, a clone not on a
# branch) and --dry-run, which change nothing; add itself (a clone, the lims profile's config,
# cron, the recipients, the control hosts' keys, lockdown-allow, a first check and a test mail,
# the sites found in Apache's and nginx's config and picked at the prompt, the section it writes);
# add again, which changes nothing; editing a section without losing its comments; sync after
# control hosts and recipients change in the inventory; list; and remove. From the repository
# directory, on a machine with podman or docker (it creates and removes three containers and a
# network named psw-fleet-*):
#   bash test/test-fleet.sh                    (Rocky 9; or name another image, such as
#   bash test/test-fleet.sh quay.io/rockylinux/rockylinux:8   or   docker.io/library/ubuntu:24.04)
set -u
image=${1:-quay.io/rockylinux/rockylinux:9}
# CONTAINER_RT=docker picks docker where both are installed, as on GitHub's runners
rt=${CONTAINER_RT:-$(command -v podman || command -v docker)} || { echo 'needs podman or docker'; exit 9; }
id=psw-fleet-$$
adm=$id-adm s1=$id-s1 s2=$id-s2
t=$(mktemp -d)
fail=0
# a failed check shows the output it looked at, if any
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; [[ -n ${out:-} ]] && head -n 40 <<< "$out" | sed "s/^/    | /"; fail=1; fi; }
on() { local c=$1; shift; $rt exec "$c" bash -c "$*"; }
# the same, with standard input passed on
on_in() { local c=$1; shift; $rt exec -i "$c" bash -c "$*"; }
# fleet as a person runs it, from the inventory's directory; without a terminal, so it can't ask
fleet() { on "$adm" "cd /inv && perl /s/fleet.pl $*" 2>&1; }
# the same with a terminal, answering the questions with $1
fleet_tty() { local answers=$1; shift; on "$adm" "cd /inv && printf '$answers' | script -qec 'perl /s/fleet.pl $*' /dev/null" 2>&1; }
inv() { on "$adm" 'cat /inv/inventory.conf'; }
trap '$rt rm -f "$adm" "$s1" "$s2" > /dev/null 2>&1; $rt network rm "$id" > /dev/null 2>&1; rm -rf "$t"' EXIT

$rt network create "$id" > /dev/null || exit 9
for c in "$adm" "$s1" "$s2"; do
    $rt run -d --name "$c" --network "$id" -v "$PWD:/s:ro,z" "$image" sleep 3600 > /dev/null || exit 9
done
web() { [[ $1 == "$s1" ]] && echo apache || { [[ $1 == "$s2" ]] && echo nginx; }; }
for c in "$adm" "$s1" "$s2"; do
    w=$(web "$c")
    on "$c" 'if command -v dnf > /dev/null; then
                 dnf -y -q install perl-interpreter openssh-clients openssh-server sudo git cronie procps-ng iproute findutils util-linux diffutils nftables '"${w/apache/httpd}"'
             else
                 apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq -y install perl openssh-client openssh-server sudo git cron procps iproute2 bsdutils diffutils nftables '"${w/apache/apache2}"'
             fi > /dev/null 2>&1' &
done
wait
ip_of() { $rt inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
aip=$(ip_of "$adm") ip1=$(ip_of "$s1") ip2=$(ip_of "$s2")
. <(on "$s1" 'cat /etc/os-release')
echo "######## $PRETTY_NAME, $(on "$adm" 'ssh -V 2>&1'), person's machine $aip, servers $ip1 and $ip2"

# the person's machine: their key, and how they reach the servers
on "$adm" "mkdir -p -m 700 /root/.ssh && ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
           for k in ctl1 ctl2; do ssh-keygen -q -t ed25519 -N '' -C fleet@\$k -f /root/\$k; done
           cat > /root/.ssh/config <<EOF
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
Host s1
    HostName $ip1
    User admin
Host s1plain
    HostName $ip1
    User plain
Host s2
    HostName $ip2
    User admin
EOF"
pub=$(on "$adm" 'cat /root/.ssh/id_ed25519.pub')
# the servers: sshd, an admin with sudo and an account without, a stand-in sendmail, a snapshot of
# this checkout to clone from, and sites in the web server's config
for c in "$s1" "$s2"; do
    on "$c" "ssh-keygen -A > /dev/null; mkdir -p /run/sshd
             sed -i '/pam_loginuid/s/^/#/' /etc/pam.d/sshd    # containers cannot set the login uid
             rm -f /run/nologin    # left by the Rocky 8 image, as if still booting
             /usr/sbin/sshd
             for u in admin plain us3; do useradd -m \$u && usermod -p '*' \$u; done
             for u in admin plain; do install -d -m 700 -o \$u /home/\$u/.ssh; echo '$pub' > /home/\$u/.ssh/authorized_keys; chown \$u /home/\$u/.ssh/authorized_keys; done
             echo 'admin ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/admin
             printf '#!/bin/sh\ncat >> /var/log/test-mail\n' > /usr/sbin/sendmail; chmod 755 /usr/sbin/sendmail
             # the snapshot: a copy root owns (the checkout may be another user's, as on GitHub's
             # runners, which git refuses to work in), committed on main (it may be a detached
             # checkout), then the admin's, to clone from
             cp -r /s /opt/src && cd /opt/src && { [ -d .git ] || git init -q; } && git add -A \
                 && git -c user.name=test -c user.email=test@example.org commit -q --allow-empty -m snapshot \
                 && git checkout -q -B main && chown -R admin /opt/src" > /dev/null || { echo "cannot set up $c"; exit 9; }
done
apache_dir=$(on "$s1" '[ -d /etc/httpd/conf.d ] && echo /etc/httpd/conf.d || echo /etc/apache2/sites-enabled')
on_in "$s1" "cat > $apache_dir/fleet-test.conf" <<'EOF'
Listen 443
<VirtualHost *:80>
    ServerName a.example.org
    ServerAlias www.a.example.org
</VirtualHost>
<VirtualHost *:80>
    ServerName b.example.org
</VirtualHost>
<VirtualHost *:80>
    ServerName localhost
</VirtualHost>
<VirtualHost *:443>
    ServerName a.example.org
</VirtualHost>
EOF
nginx_dir=$(on "$s2" '[ -d /etc/nginx/sites-enabled ] && echo /etc/nginx/sites-enabled || echo /etc/nginx/conf.d')
on_in "$s2" "cat > $nginx_dir/fleet-test.conf" <<'EOF'
server { listen 80; listen [::]:80; server_name c.example.org; location / { return 200; } }
server {
    listen 443;
    server_name d.example.org;
}
server { listen 127.0.0.1:8080; server_name e.example.org; }
EOF

# the inventory, with two control hosts: ctl1 is the person's machine, ctl2 is elsewhere
k1=$(on "$adm" 'cat /root/ctl1.pub') k2=$(on "$adm" 'cat /root/ctl2.pub')
on_in "$adm" "mkdir /inv && cat > /inv/inventory.conf" <<EOF
# a test inventory
[defaults]
mail-to = ops@example.org
lockdown-allow = 192.0.2.7
repo = /opt/src

[controller ctl1]
from = $aip
key = $k1

[controller ctl2]
from = 192.0.2.99
key = $k2
EOF
version=$(sed -n "s/^our \$VERSION = '\(.*\)';/\1/p" fleet.pl)

echo; echo "######## check and list"
out=$(fleet check); rc=$?
check 'check: a clean inventory' '((rc == 0)) && grep -qx "inventory.conf is fine: 0 server(s), 2 control host(s)" <<< "$out"'
on "$adm" 'cp /inv/inventory.conf /inv/good; printf "[s9.example.org]\nprofile = lamp\nsite = ftp://x\n[controller ctl1]\n" >> /inv/inventory.conf'
out=$(fleet check); rc=$?
check 'check: what is wrong, by line' '((rc == 1)) && grep -q "^inventory.conf:15: profile = lamp: the profiles are lims, vhost, genapp$" <<< "$out" && grep -q "^inventory.conf:16: site = ftp://x: not a URL" <<< "$out" && grep -q "^inventory.conf:17: \[controller ctl1\] again (first on line 7)$" <<< "$out"'
out=$(fleet add s1.example.org --ssh s1 --profile lims --yes); rc=$?
check 'add refuses with a broken inventory, and changes nothing' '((rc == 1)) && grep -q "fix the inventory first" <<< "$out" && on "$s1" "[[ ! -e /usr/local/sbin/php-site-watch ]]"'
on "$adm" 'cp /inv/good /inv/inventory.conf'
out=$(fleet list)
check 'list: no servers yet, two control hosts' 'grep -qx "0 server(s); control hosts: ctl1, ctl2" <<< "$out"'

echo; echo "######## add: refusals and --dry-run"
out=$(fleet add s1.example.org --ssh s1 --yes); rc=$?
check 'no profile: asks for one' '((rc == 1)) && grep -q "which profile does s1.example.org have" <<< "$out"'
out=$(fleet add s1.example.org --ssh s1plain --profile lims --yes); rc=$?
check 'no sudo: says so' '((rc == 1)) && grep -q "plain on s1.example.org cannot use sudo without a password" <<< "$out"'
out=$(fleet add s1.example.org --ssh s1 --profile lims); rc=$?
check 'nobody to ask: refuses without --yes' '((rc == 1)) && grep -q "cannot ask: standard input is not a terminal" <<< "$out"'
on "$adm" 'cp /inv/inventory.conf /inv/before'
out=$(fleet add s1.example.org --ssh s1 --profile lims --group test --dry-run); rc=$?
echo "$out" | sed 's/^/    /'
check '--dry-run: what it would do' '((rc == 0)) && grep -qx "  - clone /opt/src into ~/php_site_watch" <<< "$out" && grep -qx "  - put examples/us3lims.conf in place as /etc/php-site-watch.conf (the lims profile)" <<< "$out" && grep -qx "  - add control host ctl1 (from $aip)" <<< "$out" && grep -qx "  - add control host ctl2 (from 192.0.2.99)" <<< "$out" && grep -qx "  - let 192.0.2.7 through a lockdown (/etc/site-lockdown.conf)" <<< "$out" && grep -qx "  - send the reports to ops@example.org" <<< "$out"'
check '--dry-run: the sites in Apache'\''s config, https where on 443, without localhost or aliases' '[[ $(sed -n "s/^    \(https*:\/\/\)/\1/p" <<< "$out" | paste -sd" ") == "https://a.example.org/ http://b.example.org/" ]] && grep -qx "  note: 1 other name(s) of these sites left out, such as www.a.example.org (name them with --site to check them too)" <<< "$out"'
check '--dry-run: nothing changed' 'on "$s1" "[[ ! -e /usr/local/sbin/php-site-watch && ! -e /home/admin/php_site_watch && ! -e /etc/php-site-watch.conf ]]" && on "$adm" "cmp -s /inv/before /inv/inventory.conf"'

echo; echo "######## add"
out=$(fleet add s1.example.org --ssh s1 --profile lims --group test --yes); rc=$?
echo "$out" | sed 's/^/    /'
check 'add: done' '((rc == 0)) && grep -q "^added \[s1.example.org\] in inventory.conf" <<< "$out"'
check 'php-site-watch installed from a clone in the login'\''s home' 'on "$s1" "php-site-watch --version | grep -qx \"php-site-watch $version\" && [[ \$(stat -c %U /home/admin/php_site_watch) == admin ]]"'
check 'the lims profile'\''s config, with the recipients' 'on "$s1" "grep -qx \"user = us3\" /etc/php-site-watch.conf && grep -qx \"mail-to = ops@example.org\" /etc/php-site-watch.conf"'
check 'cron jobs mailing them' 'on "$s1" "grep -qx MAILTO=ops@example.org /etc/cron.d/php-site-watch && grep -q -- --alert /etc/cron.d/php-site-watch"'
keys=$(on "$s1" 'cat /home/fleet/.ssh/authorized_keys')
check 'both control hosts'\'' keys, limited to fleet-agent' 'grep -c "^restrict,from=\"[^\"]*\",command=\"/usr/local/sbin/fleet-agent --controller ctl[12]\" " <<< "$keys" | grep -qx 2'
check 'lockdown-allow in /etc/site-lockdown.conf' 'on "$s1" "grep -qx \"allow = 192.0.2.7\" /etc/site-lockdown.conf"'
check 'a first check, and a test mail' 'grep -q "^first check: " <<< "$out" && on "$s1" "grep -q ops@example.org /var/log/test-mail"'
out2=$(on "$adm" "ssh -i /root/ctl1 -o IdentitiesOnly=yes -o BatchMode=yes fleet@$ip1 ping" 2>&1)
check 'the control host can reach fleet-agent' 'grep -q "^fleet-agent $version on " <<< "$out2"'
sec=$(inv | sed -n '/^\[s1.example.org\]/,$p')
out=$sec
check 'the section it wrote' '[[ $(grep -v "^added = " <<< "$sec" | paste -sd"|") == "[s1.example.org]|ssh = s1|profile = lims|groups = test|site = https://a.example.org/|site = http://b.example.org/" ]] && grep -qx "added = $(on "$adm" "date +%F") by root with fleet $version" <<< "$sec"'
out=$(fleet check)
check 'and the inventory still checks' 'grep -qx "inventory.conf is fine: 1 server(s), 2 control host(s)" <<< "$out"'

# a clone that is not on a branch, which git pull cannot update
on "$s1" 'runuser -u admin -- git -C /home/admin/php_site_watch checkout -q --detach'
out=$(fleet add s1.example.org --yes); rc=$?
check 'a clone not on a branch: says how to fix it, before changing anything' '((rc == 1)) && grep -q "^fleet: ~/php_site_watch on s1.example.org is not on a branch, so git pull cannot update it; put it back on main first" <<< "$out" && ! grep -q "^-- " <<< "$out"'
on "$s1" 'runuser -u admin -- git -C /home/admin/php_site_watch checkout -q main'

echo; echo "######## add again: in line already"
on "$adm" 'cp /inv/inventory.conf /inv/before'
on "$s1" 'cp /etc/php-site-watch.conf /tmp/conf.before; : > /var/log/test-mail'
out=$(fleet add s1.example.org --yes); rc=$?
check 'only the software is updated, and checked' '((rc == 0)) && grep -q "^  - update ~/php_site_watch (git pull)" <<< "$out" && ! grep -qE "^  - (add|update|remove) control host|^  - send the reports|^  - let .* through" <<< "$out"'
check 'the inventory, the config and the keys unchanged; no test mail' 'on "$adm" "cmp -s /inv/before /inv/inventory.conf" && on "$s1" "cmp -s /tmp/conf.before /etc/php-site-watch.conf && [[ \$(grep -c \" fleet:\" /home/fleet/.ssh/authorized_keys) == 2 && \$(grep -c \"^allow\" /etc/site-lockdown.conf) == 1 && ! -s /var/log/test-mail ]]"'
# a person's comment in the section, then new sites from the command line
on "$adm" "sed -i '/^profile = lims/a # the test LIMS' /inv/inventory.conf"
out=$(fleet add s1.example.org --site https://a.example.org/uslims3/ --yes); rc=$?
sec=$(inv | sed -n '/^\[s1.example.org\]/,$p')
out2=$out; out=$sec
check '--site replaces the sites; the comment stays' '((rc == 0)) && [[ $(grep -v "^added = " <<< "$sec" | paste -sd"|") == "[s1.example.org]|ssh = s1|profile = lims|# the test LIMS|groups = test|site = https://a.example.org/uslims3/" ]]'

echo; echo "######## sync: control hosts and recipients changed in the inventory"
on "$adm" "sed -i -e 's/^mail-to = ops@example.org/mail-to = web@example.org/' -e 's/^from = $aip\$/from = $aip, 192.0.2.50/' /inv/inventory.conf
           sed -i '/^\[controller ctl2\]/,/^key = /d' /inv/inventory.conf"
out=$(fleet sync --dry-run); rc=$?
echo "$out" | sed 's/^/    /'
check 'sync --dry-run: what it would do' '((rc == 0)) && grep -qx "  - update control host ctl1 (from $aip,192.0.2.50)" <<< "$out" && grep -qx "  - remove control host ctl2 (not in the inventory)" <<< "$out" && grep -qx "  - send the reports to web@example.org" <<< "$out" && grep -qx "  - stop sending the reports to ops@example.org (not in the inventory)" <<< "$out"'
check 'and changed nothing' '[[ $(on "$s1" "cat /home/fleet/.ssh/authorized_keys") == "$keys" ]]'
out=$(fleet sync --yes); rc=$?
keys=$(on "$s1" 'cat /home/fleet/.ssh/authorized_keys')
check 'sync: ctl1 from both addresses, ctl2 gone' '((rc == 0)) && grep -q "^restrict,from=\"$aip,192.0.2.50\",command=\"/usr/local/sbin/fleet-agent --controller ctl1\" " <<< "$keys" && ! grep -q "fleet:ctl2" <<< "$keys"'
check 'sync: the reports go to web@example.org only, cron too' 'on "$s1" "[[ \$(grep \"^mail-to\" /etc/php-site-watch.conf) == \"mail-to = web@example.org\" ]] && grep -qx MAILTO=web@example.org /etc/cron.d/php-site-watch"'
out=$(fleet sync --yes); rc=$?
check 'sync again: in line' '((rc == 0)) && grep -qx "in line with the inventory" <<< "$out"'

echo; echo "######## add with nginx, picking sites at the prompt"
out=$(fleet_tty '1 3\ny\n' add s2.example.org --ssh s2 --profile vhost); rc=$?
echo "$out" | sed 's/^/    /'
check 'the sites in nginx'\''s config, numbered' 'grep -q "^   1  http://c.example.org/" <<< "$out" && grep -q "^   2  https://d.example.org/" <<< "$out" && grep -q "^   3  http://e.example.org:8080/" <<< "$out"'
sec=$(inv | sed -n '/^\[s2.example.org\]/,$p')
out2=$out; out=$sec
check 'the two picked, in the section' '((rc == 0)) && [[ $(grep "^site = " <<< "$sec" | paste -sd"|") == "site = http://c.example.org/|site = http://e.example.org:8080/" ]]'
out=$out2
check 'vhost: no ready config, so set up by hand, and no test mail yet' 'grep -q "has no settings yet" <<< "$out" && grep -q "no test mail was sent" <<< "$out" && on "$s2" "[[ ! -s /var/log/test-mail ]]"'
out=$(fleet list)
check 'list: both servers' 'grep -qE "^s1\.example\.org +s1 +lims +test +1$" <<< "$out" && grep -qE "^s2\.example\.org +s2 +vhost +- +2$" <<< "$out" && grep -qx "2 server(s); control hosts: ctl1" <<< "$out"'
check 'list --group, --names' '[[ $(fleet list --group test --names) == s1.example.org && $(fleet list --group vhost --names) == s2.example.org ]]'

echo; echo "######## remove"
out=$(fleet remove s2.example.org --uninstall --yes); rc=$?
check 'remove --uninstall: keys and software gone there, section gone here' '((rc == 0)) && on "$s2" "[[ ! -e /usr/local/sbin/php-site-watch ]] && ! grep -q fleet: /home/fleet/.ssh/authorized_keys" && ! inv | grep -q "s2.example.org"'
out=$(fleet remove s1.example.org --forget --yes); rc=$?
check 'remove --forget: only the inventory' '((rc == 0)) && ! inv | grep -q "^\[s1.example.org\]" && on "$s1" "[[ -x /usr/local/sbin/php-site-watch ]]" && inv | grep -q "^\[controller ctl1\]"'

echo; ((fail)) && echo 'SOME TESTS FAILED' || echo 'all fleet tests passed'
exit $fail
