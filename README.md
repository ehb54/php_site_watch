# php_site_watch

`php-site-watch` checks an Apache or nginx + PHP server for signs of exploitation or trouble. It
can mail an alert within the hour when something new shows up, and a status report every morning
that also covers basic server health. Each scheduled run is logged, and the latest reports can be
read on the server at any time.

It was written after the PHP2Shell vulnerabilities
([CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)),
whose attacks leave crashed or out-of-memory PHP workers behind, but it is a useful daily check
for any PHP site.

It reports:

- PHP workers that crashed (`SIGSEGV`, `SIGBUS`, `SIGABRT`) or died while starting a request,
  from php-fpm logs and from Apache when it runs PHP itself (mod_php)
- PHP running out of memory or time, and php-fpm reaching its worker limit
- FastCGI failures between the web server and PHP, such as reset connections or unreadable
  headers (PHP's own notices and warnings, which Apache logs as `AH01071`, and the "Primary
  script unknown" noise from scanners are left out)
- for context: PHP fatal errors in your applications, grouped by message; 5xx responses; and
  the clients sending the most POST requests
- files the PHP account changed recently, such as a dropped web shell
- processes the PHP account is running other than web server and PHP workers
- network sockets of the PHP account other than web visitors and local connections, such as a
  listening backdoor or an outbound connection
- server health: uptime and load, whether the web server and php-fpm services are running,
  local disks over 90% full, the PHP version and whether its packages include the PHP2Shell fix
  (RPM, Debian and Ubuntu), whether php-fpm, or Apache with mod_php, is still running PHP that an
  update replaced, and zombie processes of the PHP account

On a host, processes in containers (Docker, Podman, Kubernetes, LXC) are left out: they can run
under the same user ID as the host's PHP but belong to their own setups. The health section notes
how many containers are running. To watch PHP in a container, run php-site-watch inside it (see
[Containers](#containers)).

Two companions come with it, for when something is found:
[`site-lockdown`](#emergency-lockdown), an emergency switch that blocks the web ports (and MySQL on
request) from everywhere but your own addresses, and [`fleet-agent`](#fleet-control-hosts), the one
command a fleet control host may run on the server: it reads reports and can turn the lockdown on,
never off.

## Requirements

- Linux, run as root (to read the logs and see every process and socket)
- `perl` with no extra modules (tested with Perl 5.26 to 5.40), plus `ps`, `ss` and `find`.
  On RHEL, Rocky or Oracle Linux: `dnf install perl-interpreter procps-ng iproute findutils git`.
  On Debian or Ubuntu, where perl and find are always there: `apt-get install procps iproute2 git`
- For the scheduled runs: cron (`cronie`, or `cron` on Debian and Ubuntu), a local `sendmail`
  such as postfix configured to send outgoing mail, and `logrotate` for the run log
- For `site-lockdown`: nftables (`dnf install nftables`, or `apt-get install nftables`; the
  `nftables` service itself need not run), and systemd to keep the block in place across reboots.
  For fleet control hosts: `sudo` and OpenSSH 7.2 or later

Tested on Rocky Linux 8.10, 9.8 and 10.2, including live Apache + php-fpm setups (PHP 7.4.33,
8.0.30 and 8.3.36) delivering through postfix, and in Ubuntu 20.04, 22.04 and 24.04 and Debian 12 and 13 containers,
including the `docker exec` setup described under [Containers](#containers). `site-lockdown` and
`fleet-agent` are tested in Rocky Linux 8, 9 and 10 and Ubuntu 20.04, 22.04 and 24.04 containers
(nftables 0.9.3 to 1.1.5), from a second and third container on the same network. It reads php-fpm,
PHP, Apache and nginx log formats, including rotated `.gz` files, and has read the Apache logs of
an Ubuntu 20.04 container running PHP 7.4 as mod_php.

## Install, update, uninstall

```bash
git clone https://github.com/ehb54/php_site_watch
cd php_site_watch
sudo ./setup.sh install --cron --mailto you@example.org
```

This installs `/usr/local/sbin/php-site-watch` (use the full path with `sudo`: on RHEL and
similar systems its safe PATH leaves out `/usr/local/sbin`), a fully commented
`/etc/php-site-watch.conf` (only if there isn't one yet), a logrotate entry for the run log, and
`/etc/cron.d/php-site-watch` with two jobs that mail to the recipients in the config. `--mailto`
adds recipients there (comma-separated); with none, cron mails the reports to root instead.
It also installs `/usr/local/sbin/site-lockdown` with its systemd units and a commented
`/etc/site-lockdown.conf`, and `/usr/local/sbin/fleet-agent`; neither does anything until used.

On an UltraScan LIMS server, start from the example configuration, which allows what the LIMS
normally does as `us3`:

```bash
sudo cp examples/us3lims.conf /etc/php-site-watch.conf
```

That replaces the whole config, recipients included; add them back with `sudo ./setup.sh mail add`.

- **alerts**, hourly at 5 past: findings from today and yesterday that haven't been reported
  before. Nothing is sent when there is nothing new. Each finding is mailed once; the list of
  what was sent is kept in `/var/lib/php-site-watch` for 14 days.
- **status**, daily at 07:00: the full report on the previous day plus server health. The
  subject says `OK`, the number of findings, or which health check needs attention, so a
  missing report also tells you something is wrong.

Scheduled runs take turns: an alert that finds the previous run still going skips that hour, and
the run log says so; the status report waits for its turn.

`--mailfrom ADDRESS` sets the sender, if your mail relay needs a particular one. Leave out
`--cron` to install the script only. For PHP sites in containers, see [Containers](#containers).

Who gets the reports:

```bash
./setup.sh mail list                            # current recipients
sudo ./setup.sh mail add colleague@example.org  # one or more addresses
sudo ./setup.sh mail remove colleague@example.org
sudo ./setup.sh mail from watch@example.org     # sender address, or none for the system's
sudo ./setup.sh mail test                       # mail a status report to everyone now
```

Recipients are the `mail-to` lines of `/etc/php-site-watch.conf`, so editing that file works
too; `setup.sh` also keeps cron's address for error mail in step. Updating from a version
before 1.4.0 moves the addresses from the cron jobs into the config.

Later:

```bash
sudo ./setup.sh update             # pull the latest version and reinstall; config and cron job are kept
sudo ./setup.sh uninstall          # remove the scripts, cron job, logrotate entry, site-lockdown units and the
                                   # control hosts' sudo rule; config, history and logs are kept
sudo ./setup.sh uninstall --purge  # also remove the configs, /var/lib/php-site-watch, the logs, site-lockdown's
                                   # state and the fleet user with its keys
```

Uninstall refuses while a lockdown is on, so the block never stays behind without the command
that removes it.

To change the schedule, edit `/etc/cron.d/php-site-watch`; running `setup.sh install --cron`
again rewrites it.

## Use

```bash
sudo /usr/local/sbin/php-site-watch                      # today, printed
sudo /usr/local/sbin/php-site-watch --date yesterday     # or YYYY-MM-DD, in the server's local time
sudo /usr/local/sbin/php-site-watch --quiet              # print only findings, nothing if all is clean
sudo /usr/local/sbin/php-site-watch --status --mail-to you@example.org   # mail the daily report now
```

Exit status: 0 nothing suspicious, 1 findings, 2 usage or setup error. A plain run never mails,
even with recipients configured.

### Seeing what the scheduled runs found

Each `--alert` and `--status` run adds a line to `/var/log/php-site-watch.log`, rotated monthly:

```
2026-10-22 07:00:02  status  2026-10-21: OK; mailed to you@example.org
2026-10-22 08:05:01  alert   2026-10-21 and 2026-10-22: 2 findings, 1 new; mailed to you@example.org
2026-10-22 09:05:01  alert   2026-10-21 and 2026-10-22: 2 findings, 0 new; nothing new to send
```

The latest status report and alert are also saved, as mailed, in `/var/lib/php-site-watch`
(readable by root only, since they name IP addresses, files and processes). To see the recent
runs and both reports without running the checks again:

```bash
sudo /usr/local/sbin/php-site-watch --last
tail -f /var/log/php-site-watch.log      # follow the scheduled runs
```

Options (all but `--quiet`, `--alert`, `--status`, `--last` and `--version` can also be set in
`/etc/php-site-watch.conf`; see [php-site-watch.conf.example](php-site-watch.conf.example),
[examples/us3lims.conf](examples/us3lims.conf) for an UltraScan LIMS server, and
[examples/genapp.conf](examples/genapp.conf) for a GenApp container):

| Option | Meaning |
|---|---|
| `--date DAY` | day to check: `YYYY-MM-DD`, `today` or `yesterday` (default: today) |
| `--hours N` | how far back to look for changed files (default: 24) |
| `--user NAME` | account PHP runs as (default: detected from running workers) |
| `--fpm-logs PATH` | php-fpm log directory or file (repeatable) |
| `--web-logs PATH` | Apache or nginx log directory or file (repeatable) |
| `--scan DIR` | where to look for changed files (repeatable; replaces the default directories below) |
| `--exclude REGEX` | changed files to ignore (repeatable); one naming a whole directory, like `^/srv/app/cache/`, also skips that directory during the scan |
| `--allow-proc REGEX` | other expected processes of the PHP account (repeatable) |
| `--allow-peer REGEX` | expected connections to other machines, as host:port (repeatable) |
| `--config FILE` | config file (default: `/etc/php-site-watch.conf` if it exists) |
| `--quiet` | print only sections with findings |
| `--alert` | report only findings not reported before, from today and yesterday |
| `--status` | full report plus server health |
| `--mail-to ADDRESSES` | with `--alert` or `--status`, mail instead of printing (comma-separated; replaces the config's recipients) |
| `--mail-from ADDRESS` | sender address for mail |
| `--last` | print the recent scheduled runs and their latest saved reports, without checking |
| `--log-file FILE` | run log for `--alert` and `--status` (default: `/var/log/php-site-watch.log`; `none` turns it off) |
| `--state-dir DIR` | alert history and saved reports (default: `/var/lib/php-site-watch`) |
| `--sendmail PATH` | program that sends the mail (default: `/usr/sbin/sendmail`) |
| `--version` | print the version |

The PHP fatal error, 5xx, POST and health sections are for context and don't count as
findings. The files, processes, sockets and health sections show the current state, whatever
`--date` is.

Without `scan` lines, it looks for changed files where the PHP account's files matter:
- the document roots and aliases in the Apache and nginx configuration;
- the directories PHP is set to use: php-fpm `chdir`, `open_basedir`, and the upload and temporary directories;
- the account's home, following a link to where it really is;
- `/tmp`, `/var/tmp`, `/dev/shm` and `/var/www`.

The health section of the report lists these directories and how long the scan took. Before 1.7.0
it walked all of `/srv`. On some servers that also holds backups, data and other users' homes, and
walking it took a long time on spinning disks. If the scan is still slow, list the directories
yourself with `scan` lines.

## Reading the results

- **Usually harmless:** an occasional out-of-memory or time-limit error from a known page, 5xx
  responses to scanners, and files your applications normally write. Add those to `exclude` once
  you know them, so they stop being reported.
- **Worth a closer look:** crashed workers, especially several within seconds; FastCGI errors
  next to POSTs from the same client; new `.php` files in web directories or anything in `/tmp`
  or `/dev/shm`; processes or listening sockets of the PHP account you don't recognize; and
  connections from it to unfamiliar addresses.
- **Health lines marked `!!`:** a web server or php-fpm service that is enabled but not running,
  a disk over 90% full, a PHP package without the PHP2Shell fix, a php-fpm that needs a restart
  to pick up an update, an Apache with mod_php that needs a stop and start for it, a lockdown
  that is on (or on with its rules gone), and a key for the `fleet` user that isn't limited to
  `fleet-agent`.

## The PHP2Shell fix check

Distributions backport the fix without changing PHP's own version (7.4.33 stays 7.4.33), so the
health section looks for `CVE-2026-109618` in the changelog of the installed packages instead:

- RPM systems (RHEL, Rocky, AlmaLinux, Oracle Linux): `rpm -q --changelog` of the package that
  provides the running php-fpm, or the `php` command.
- Packages that follow PHP's own releases instead of backporting, such as RHEL 10 and Rocky 10
  (whose changelog says only `rebase to 8.3.36`), Remi's or Ondřej Surý's: PHP's releases with
  the fix are 8.2.35, 8.3.36, 8.4.27 and 8.5.12, so those versions or later count as fixed
  (`yes (8.3.36 is a PHP release with the fix)`). Older branches (7.4, 8.0, 8.1) only get the
  fix as a distribution backport.
- Debian and Ubuntu: `/usr/share/doc/phpX.Y-common/changelog.Debian.gz`, once for each PHP
  version installed. The packages of a version (`phpX.Y-cli`, `libapache2-mod-phpX.Y`,
  `phpX.Y-fpm` and so on) are built together, so this covers mod_php as well.

The line ends in `yes`, `NO` (also listed with `!!` at the top), or, on Debian and Ubuntu,
`unknown (no changelog)`. Docker's Ubuntu images keep these changelogs, but minimized systems that
leave all of `/usr/share/doc` out, such as Debian's slim images, don't. There, compare the version
on that line with the builds below. To keep the changelog from the next PHP update on, put this
line in a file of its own in `/etc/dpkg/dpkg.cfg.d`, such as `zz-php-changelog` (it has to sort
after the file that leaves the documentation out), before installing the update:

```
path-include=/usr/share/doc/php*/changelog.Debian.gz
```

Builds with the fix:

| System | PHP | Fixed in |
|---|---|---|
| Ubuntu 20.04 | php7.4 | `7.4.3-4ubuntu2.29+esm5` (USN-8948-2, Ubuntu Pro) |
| Ubuntu 22.04 | php8.1 | `8.1.2-1ubuntu2.28` (USN-8948-1) |
| Ubuntu 24.04 | php8.3 | `8.3.6-0ubuntu0.24.04.13` (USN-8948-1) |
| RHEL 8, Rocky, AlmaLinux, Oracle Linux 8 | php 7.4 module | `7.4.33-8` |
| Rocky 9 | php 8.0 | `8.0.30-8.el9_8.1` |
| RHEL 10, Rocky 10 | php 8.3 | `8.3.36-1` (PHP 8.3.36) |

The check reads the installed packages, but a running PHP keeps the code it started with. The
health section flags a php-fpm that still runs a binary an update replaced, and an Apache that
still runs a PHP module (mod_php) an update replaced. Apache keeps the old module through graceful
restarts (`apachectl graceful`, `apachectl restart`, `service apache2 reload`), so after a PHP
update stop and start it: `service apache2 restart` or `systemctl restart apache2` do that.

## Containers

Run inside a container, php-site-watch watches that container: its logs, files, processes and
sockets. Containers often run no cron or mail server, so put it in each container and run it
there from the host's cron with `docker exec` (`podman exec` works the same); cron mails what it
prints. For a container called `web1`, from the clone on the host:

```bash
sudo docker cp php-site-watch.pl web1:/usr/local/sbin/php-site-watch
sudo docker cp examples/genapp.conf web1:/etc/php-site-watch.conf    # or settings of your own
sudo docker exec web1 /usr/local/sbin/php-site-watch                 # today's report
```

Then add the jobs to the host's cron, for example in `/etc/cron.d/php-site-watch-containers`:

```
MAILTO=you@example.org
5 * * * * root docker exec web1 /usr/local/sbin/php-site-watch --alert
0 7 * * * root docker exec web1 /usr/local/sbin/php-site-watch --status --date yesterday
```

With no `mail-to` in the container's config, `--alert` prints only when there is something new
and `--status` prints its report every day, so cron mails exactly those. The alert history and
run log stay in the container, and start afresh when it is created again. `docker exec` runs as
the container's root unless the image names another user; then add `-u root`. Copy the script
again after updating the clone. [examples/genapp.conf](examples/genapp.conf) is for GenApp
containers (Apache with mod_php, PHP running as `www-data`).

Docker gives a container's root no `CAP_SYS_PTRACE`, which `ss` needs to tell which process owns
a socket, so the report warns that the sockets section is incomplete. To see the PHP account's
sockets too, create the container with `--cap-add SYS_PTRACE`. Inside a container, the disk line
shows the container's `/` as the host disk it is stored on.

Updating packages inside a running container doesn't restart its services (Docker's Ubuntu images
refuse it during installs), so after updating PHP there, stop and start Apache yourself, for
example `docker exec web1 service apache2 restart` (or restart the container, if Apache is its
main process); until then the health section says Apache still runs the replaced PHP module.

A plain run (no `--alert` or `--status`) writes nothing, so it can also check a snapshot of a
container, such as an image made with `docker commit`, in a throwaway container that starts none
of its services. Nothing runs there, so name the PHP account, check one day at a time with
`--date`, and set `--hours`, which counts back from now, to cover the changed files of interest:

```bash
sudo docker run --rm --read-only --network none \
    -v "$PWD/php-site-watch.pl:/usr/local/sbin/php-site-watch:ro" \
    -v "$PWD/examples/genapp.conf:/etc/php-site-watch.conf:ro" \
    --entrypoint /usr/local/sbin/php-site-watch snapshot-image:tag \
    --user www-data --date 2026-10-21 --hours 72
```

The options after the image name are php-site-watch's. Only the logs, files and health mean
something there; the processes and sockets are those of the throwaway container.

## Emergency lockdown

When a vulnerability is being exploited and no fix is installed yet, `site-lockdown` blocks the
web ports to the server from everywhere except the addresses you allow:

```bash
sudo /usr/local/sbin/site-lockdown on --reason "CVE-2026-12345, no fix yet"
sudo /usr/local/sbin/site-lockdown on --mysql      # add MySQL while it is on
sudo /usr/local/sbin/site-lockdown status
sudo /usr/local/sbin/site-lockdown off
```

- **What it blocks:** TCP and UDP 80 and 443 to the server, and with `--mysql` TCP 3306 as well.
  UltraScan's desktop clients use MySQL, so `--mysql` is for a MySQL or MariaDB vulnerability or a
  full lockdown. Connections already open on those ports are cut.
- **What still gets through:** SSH, always; traffic from the server itself and from its containers
  and VMs; and the addresses in `/etc/site-lockdown.conf` (`allow = ADDRESS or NETWORK`), so you
  can check a site before opening it again. The ports can be changed there too. Run
  `site-lockdown on` again while it is on to apply changes.
- **How:** an nftables table of its own, `inet site_lockdown`, which runs before firewalld's and
  Docker's rules and before address translation. So ports Docker publishes for containers are
  blocked too, on firewalld and Ubuntu hosts alike, and firewalld's and Docker's own rules are
  left alone.
- **Staying on:** `site-lockdown on` enables `site-lockdown.service`, which puts the block back at
  boot right after firewalld and before the network comes up, so a rebooting server is never
  reachable on the blocked ports, and again after every restart of firewalld or
  `nftables.service`. `site-lockdown.timer` also checks every minute, for anything else that
  removes it, such as `nft flush ruleset`. `off` disables them. Without systemd, run
  `site-lockdown enforce` after such events.
- **Seeing it:** `status` says since when, who turned it on and why, what is blocked and how many
  packets were dropped. Every change goes to `/var/log/site-lockdown.log` and to syslog, and the
  daily status report shows a lockdown at the top (`!! LOCKDOWN on, since ...`) until it is off.
- **Limits:** a firewall can't tell the sites on one server apart, so it blocks all of them. And
  someone who already has root on the server can remove it; for that, block outside the server,
  such as with the cloud's security groups or at the network's firewall.

## Fleet control hosts

A control host is a machine that looks after many servers over SSH. On each server it gets a key
that can only run `fleet-agent`, which accepts five requests:

| Request | What it does |
|---|---|
| `ping` | the server's name and versions |
| `report` | the latest saved reports and runs (`php-site-watch --last`) |
| `packages` | installed packages, and the security updates the package manager already knows about (nothing is downloaded) |
| `lockdown status` | `site-lockdown status` |
| `lockdown on [--mysql] [REASON]` | turns the lockdown on, recorded as done by that control host |

Turning the lockdown off, installing software and changing settings can't be done through it, so a
stolen control host key can read reports and lock sites, and nothing else. Every request, refused
or not, goes to syslog (authpriv).

```bash
sudo ./setup.sh controller add ctl1 --from 203.0.113.10 --key 'ssh-ed25519 AAAA...'
./setup.sh controller list
sudo ./setup.sh controller remove ctl1
```

`controller add` creates a `fleet` user without a password (its `~/.ssh` belongs to root, so it
can't add keys of its own), a key line limited to `fleet-agent` and to the given addresses
(`restrict,from="...",command="..."`), and a sudo rule that lets `fleet-agent` run itself as root,
where it checks the request again. If sshd only lets listed users in (`AllowUsers`), it prints
the line to add. Then, from the control host:

```bash
ssh fleet@server report
ssh fleet@server lockdown on --mysql CVE-2026-12345 exploited, no fix yet
```

The daily status report lists the control hosts (`fleet control hosts: ctl1 (from 203.0.113.10)`)
and flags any key of the `fleet` user that isn't limited this way.

## Tests

`test/` holds sample logs with planted problems, fixture changelogs and test scripts, which print
`ok` or `FAIL` per check. Run them in throwaway containers from the repository directory (the
Rocky ones work with `:8`, `:9` and `:10`):

```bash
# sample logs, planted files, processes and sockets, mail through a stand-in sendmail,
# the run log and --last (SYS_PTRACE lets container root see socket owners, as real root can)
podman run --rm -q --cap-add SYS_PTRACE -v "$PWD/test:/t:ro,z" -v "$PWD:/s:ro,z" \
    quay.io/rockylinux/rockylinux:9 bash /t/test-run.sh
# real Apache + php-fpm and postfix (:8, :9 or :10): crashed workers, out-of-memory, the PHP2Shell
# fix check before and after updating PHP, and php-fpm still running the replaced binary
podman run --rm -q -v "$PWD/test:/t:ro,z" -v "$PWD:/s:ro,z" \
    quay.io/rockylinux/rockylinux:10 bash /t/test-el-live.sh
# setup.sh: install, cron jobs, recipients, moving addresses off old cron jobs, logrotate,
# uninstall (also with Ubuntu and Debian images, e.g. docker.io/library/ubuntu:22.04)
podman run --rm -q -v "$PWD:/s:ro,z" quay.io/rockylinux/rockylinux:9 bash /s/test/test-setup.sh
# Ubuntu: the PHP2Shell fix check through dpkg with fixture packages, missing ps and ss, the disk
# line in a container, examples/genapp.conf (:20.04, :22.04 or :24.04, or debian:12-slim; run it
# a second time with --cap-add SYS_PTRACE for the other half of the sockets checks)
podman run --rm -q -v "$PWD:/s:ro,z" docker.io/library/ubuntu:22.04 bash /s/test/test-ubuntu.sh
# real Apache with mod_php on Ubuntu (:20.04, :22.04 or :24.04): crashed workers, out-of-memory,
# the fix check on the archive's packages, and Apache still running the old PHP after an update
podman run --rm -q -v "$PWD:/s:ro,z" docker.io/library/ubuntu:22.04 bash /s/test/test-ubuntu-live.sh
```

`docker run` works the same way. One more test runs on a Docker host itself and follows
[Containers](#containers): `docker exec` as the host's cron would run it, and a snapshot check:

```bash
bash test/test-docker.sh      # or: bash test/test-docker.sh ubuntu:20.04
```

`site-lockdown` and `fleet-agent` need a network of containers, so their test also runs on the
container host itself, with podman or docker (it creates and removes three containers and a
network):

```bash
# the block seen from another container, allowed addresses, enforce, and fleet-agent over SSH:
# what a control host may and may not do, its address limit, the health lines, uninstall
bash test/test-lockdown.sh    # Rocky 9; or name an image, e.g. docker.io/library/ubuntu:20.04
```

## Versions

- **1.9.1:** after a reboot, `site-lockdown` restores the block before the network comes up, instead
  of after Docker (which left a locked-down server reachable for a few seconds), and again after
  every firewalld restart; the timer runs a separate check unit
- **1.9.0:** `site-lockdown`, an emergency block for the web ports and optionally MySQL that only
  a person can lift; `fleet-agent` and `setup.sh controller add|list|remove` for fleet control
  hosts; the status report shows a lockdown and the control hosts, and flags unrestricted keys;
  PHP releases with the PHP2Shell fix (8.3.36 and so on) count as fixed, for Rocky 10's PHP,
  whose changelog doesn't name the CVE; tested on Rocky 10
- **1.8.0:** an Apache still running a PHP module an update replaced (mod_php) is flagged, with
  advice to stop and start it, since a graceful restart keeps the old module; `setup.sh` on
  Debian and Ubuntu: apt package hints, and `--cron` checks that cron itself is installed
- **1.7.1:** a home that is a link (`/home/us3` to `/srv/users/us3`) is scanned under its usual
  name, so exclude patterns match; scheduled runs take turns instead of piling up; an exclude
  naming a whole directory (`^/dir/`) also skips it during the scan; the LIMS example leaves out
  the analysis jobs' work and result directories, `us3`'s shell history, and CAPTCHA backgrounds
  in any one-level subdirectory such as `bak/`
- **1.7.0:** the changed-file scan takes its directories from the web server and PHP configuration
  instead of walking all of `/srv`; the health section shows where it looked and how long it took
- **1.6.0:** Debian and Ubuntu: PHP2Shell fix check through dpkg; in containers: the disk line
  shows the host disk under `/` instead of mounted files such as `/etc/hosts`, and a warning when
  the PHP account's sockets can't be seen; plain warnings for a missing `ss`, `ps` or `find`;
  `examples/genapp.conf`; how to run it in containers
- **1.5.0:** run log `/var/log/php-site-watch.log`, saved latest status and alert reports, `--last`
- **1.4.1:** fix moving addresses off old cron jobs that have no `--mail-from`
- **1.4.0:** recipients kept in the config; `setup.sh mail list|add|remove|from|test`
- **1.3.0:** container processes left out; zombie processes summarized; `examples/us3lims.conf`
- **1.2.0:** only real FastCGI failures count; PHP fatal errors listed for context
- **1.1.0:** first published version: hourly alerts, daily status with server health, `setup.sh`
