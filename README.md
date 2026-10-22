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
  (RPM, Debian and Ubuntu), whether php-fpm is still running a binary an update replaced, and
  zombie processes of the PHP account

On a host, processes in containers (Docker, Podman, Kubernetes, LXC) are left out: they can run
under the same user ID as the host's PHP but belong to their own setups. The health section notes
how many containers are running. To watch PHP in a container, run php-site-watch inside it (see
[Containers](#containers)).

## Requirements

- Linux, run as root (to read the logs and see every process and socket)
- `perl` with no extra modules (tested with Perl 5.26 to 5.40), plus `ps`, `ss` and `find`.
  On RHEL, Rocky or Oracle Linux: `dnf install perl-interpreter procps-ng iproute findutils git`.
  On Debian or Ubuntu, where perl and find are always there: `apt-get install procps iproute2 git`
- For the scheduled runs: cron (`cronie`, or `cron` on Debian and Ubuntu), a local `sendmail`
  such as postfix configured to send outgoing mail, and `logrotate` for the run log

Tested on Rocky Linux 8.10 and 9.8, including a live Apache 2.4.37 + php-fpm 7.4.33 setup
delivering through postfix, and in Ubuntu 20.04, 22.04 and 24.04 and Debian 12 and 13 containers,
including the `docker exec` setup described under [Containers](#containers). It reads php-fpm,
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
sudo ./setup.sh uninstall          # remove the script, cron job and logrotate entry; config, history and log are kept
sudo ./setup.sh uninstall --purge  # also remove /etc/php-site-watch.conf, /var/lib/php-site-watch and the run log
```

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
| `--exclude REGEX` | changed files to ignore (repeatable) |
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
  a disk over 90% full, a PHP package without the PHP2Shell fix, or a php-fpm that needs a
  restart to pick up an update.

## The PHP2Shell fix check

Distributions backport the fix without changing PHP's own version (7.4.33 stays 7.4.33), so the
health section looks for `CVE-2026-109618` in the changelog of the installed packages instead:

- RPM systems (RHEL, Rocky, AlmaLinux, Oracle Linux): `rpm -q --changelog` of the package that
  provides the running php-fpm, or the `php` command.
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

## Tests

`test/` holds sample logs with planted problems, fixture changelogs and test scripts, which print
`ok` or `FAIL` per check. Run them in throwaway containers from the repository directory (the
Rocky ones work with `:8` and `:9`):

```bash
# sample logs, planted files, processes and sockets, mail through a stand-in sendmail,
# the run log and --last (SYS_PTRACE lets container root see socket owners, as real root can)
podman run --rm -q --cap-add SYS_PTRACE -v "$PWD/test:/t:ro,z" -v "$PWD:/s:ro,z" \
    quay.io/rockylinux/rockylinux:9 bash /t/test-run.sh
# real Apache + php-fpm 7.4 and postfix: crashed workers, out-of-memory, PHP2Shell fix check
podman run --rm -q -v "$PWD/test:/t:ro,z" -v "$PWD:/s:ro,z" \
    quay.io/rockylinux/rockylinux:8 bash /t/test-el8-live.sh
# setup.sh: install, cron jobs, recipients, moving addresses off old cron jobs, logrotate, uninstall
podman run --rm -q -v "$PWD:/s:ro,z" quay.io/rockylinux/rockylinux:9 bash /s/test/test-setup.sh
# Ubuntu: the PHP2Shell fix check through dpkg with fixture packages, missing ps and ss, the disk
# line in a container, examples/genapp.conf (:20.04, :22.04 or :24.04, or debian:12-slim; run it
# a second time with --cap-add SYS_PTRACE for the other half of the sockets checks)
podman run --rm -q -v "$PWD:/s:ro,z" docker.io/library/ubuntu:22.04 bash /s/test/test-ubuntu.sh
```

`docker run` works the same way. One more test runs on a Docker host itself and follows
[Containers](#containers): `docker exec` as the host's cron would run it, and a snapshot check:

```bash
bash test/test-docker.sh      # or: bash test/test-docker.sh ubuntu:20.04
```

## Versions

- **1.7.1:** a home that is a link (`/home/us3` to `/srv/users/us3`) is scanned under its usual
  name, so exclude patterns match; scheduled runs take turns instead of piling up; the LIMS example
  leaves out the analysis jobs' work directories, `us3`'s shell history, and CAPTCHA backgrounds
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
