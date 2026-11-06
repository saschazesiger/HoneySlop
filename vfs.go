package main

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// VFile is a file or directory of the simulated host whose content and permissions are fixed.
// Everything not in the VFS is improvised by the LLM, but security relevant files live here so
// permissions are enforced in Go and contents never drift.
type VFile struct {
	Path     string
	Dir      bool
	Owner    string
	Group    string
	Mode     uint32 // permission bits, e.g. 0o640
	Content  string
	MTime    time.Time
	Complete bool // directory listing is fully known (ls is answered deterministically)
}

func (f *VFile) Size() int {
	if f.Dir {
		return 4096
	}
	return len(f.Content)
}

// ModeString renders "-rw-r-----" / "drwxr-x---".
func (f *VFile) ModeString() string {
	b := []byte("----------")
	if f.Dir {
		b[0] = 'd'
	}
	const rwx = "rwxrwxrwx"
	for i := 0; i < 9; i++ {
		if f.Mode&(1<<uint(8-i)) != 0 {
			b[i+1] = rwx[i]
		}
	}
	return string(b)
}

// ---------- permission model ----------

func (w *World) groupsOf(user string) []string {
	a := w.Unix[user]
	if a == nil {
		return []string{user}
	}
	gs := []string{primaryGroup(a)}
	return append(gs, a.Groups...)
}

func primaryGroup(a *UnixAccount) string {
	switch a.GID {
	case 0:
		return "root"
	default:
		return a.Name
	}
}

// permBits returns the rwx triple of f that applies to user.
func (w *World) permBits(f *VFile, user string) uint32 {
	if user == "root" {
		return 7
	}
	if f.Owner == user {
		return (f.Mode >> 6) & 7
	}
	for _, g := range w.groupsOf(user) {
		if g == f.Group {
			return (f.Mode >> 3) & 7
		}
	}
	return f.Mode & 7
}

// Lookup returns the VFS entry for an absolute, cleaned path.
func (w *World) Lookup(p string) *VFile { return w.files[path.Clean(p)] }

// AccessError describes why a path can't be accessed ("" = allowed / unknown to the VFS).
// want is a combination of 'r', 'w', 'x'.
func (w *World) AccessError(user, p, want string) string {
	p = path.Clean(p)
	if user == "root" {
		return ""
	}
	// every ancestor directory needs search (x) permission
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := ""
	for i := 0; i < len(parts)-1; i++ {
		cur += "/" + parts[i]
		if d := w.files[cur]; d != nil && d.Dir && w.permBits(d, user)&1 == 0 {
			return "Permission denied"
		}
	}
	f := w.files[p]
	if f == nil {
		return ""
	}
	bits := w.permBits(f, user)
	for _, c := range want {
		switch {
		case c == 'r' && bits&4 == 0, c == 'w' && bits&2 == 0, c == 'x' && bits&1 == 0:
			return "Permission denied"
		}
	}
	return ""
}

// Children lists the direct entries of a directory, sorted.
func (w *World) Children(dir string) []*VFile {
	dir = path.Clean(dir)
	var out []*VFile
	for p, f := range w.files {
		if p != dir && path.Dir(p) == dir {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// ProtectedPaths lists VFS paths user can't read (given to the LLM as hard facts).
func (w *World) ProtectedPaths(user string) []string {
	var out []string
	for p, f := range w.files {
		want := "r"
		if f.Dir {
			want = "rx"
		}
		if w.AccessError(user, p, want) != "" {
			if parent := w.files[path.Dir(p)]; parent != nil && w.AccessError(user, parent.Path, "rx") != "" {
				continue // covered by the parent
			}
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// ReadableFiles lists VFS files user can read (path + content given to the LLM for consistency).
func (w *World) ReadableFiles(user string) []*VFile {
	var out []*VFile
	for p, f := range w.files {
		if !f.Dir && w.AccessError(user, p, "r") == "" {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// ---------- file contents ----------

func buildFiles(w *World) map[string]*VFile {
	fs := map[string]*VFile{}
	base := w.Created
	ago := func(d, h int) time.Time {
		return base.Add(-time.Duration(d)*24*time.Hour - time.Duration(h)*time.Hour - 17*time.Minute)
	}
	dir := func(p, owner, group string, mode uint32, mt time.Time, complete bool) {
		fs[p] = &VFile{Path: p, Dir: true, Owner: owner, Group: group, Mode: mode, MTime: mt, Complete: complete}
	}
	file := func(p, owner, group string, mode uint32, mt time.Time, content string) {
		fs[p] = &VFile{Path: p, Owner: owner, Group: group, Mode: mode, MTime: mt, Content: content}
	}

	dir("/", "root", "root", 0o755, ago(400, 0), false)
	for _, d := range []string{"/etc", "/var", "/opt", "/usr", "/home", "/proc", "/tmp", "/var/log", "/var/backups"} {
		dir(d, "root", "root", 0o755, ago(30, 2), false)
	}
	fs["/tmp"].Mode = 0o777 // sticky dir, simplified
	fs["/home"].Complete = true

	// ----- /etc -----
	var pw, sh, grp strings.Builder
	pw.WriteString(`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
deploy:x:1001:1001:Deploy User,,,:/home/deploy:/bin/bash
redis:x:113:118::/var/lib/redis:/usr/sbin/nologin
postfix:x:114:119::/var/spool/postfix:/usr/sbin/nologin
`)
	days := int(base.Sub(time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)).Hours() / 24)
	shadowLine := func(name, hash string, changed int) {
		fmt.Fprintf(&sh, "%s:%s:%d:0:99999:7:::\n", name, hash, changed)
	}
	shadowLine("root", w.Unix["root"].Hash, days-212)
	for _, n := range []string{"daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
		"systemd-network", "systemd-resolve", "systemd-timesync", "messagebus", "syslog", "_apt", "tss", "uuidd", "tcpdump", "sshd", "landscape", "pollinate", "usbmux"} {
		shadowLine(n, "*", days-1100)
	}
	shadowLine("systemd-coredump", "!!", days-1100)
	shadowLine("ubuntu", w.Unix["ubuntu"].Hash, days-640)
	shadowLine("lxd", "!", days-1100)
	shadowLine("deploy", w.Unix["deploy"].Hash, days-905)
	shadowLine("redis", "*", days-1020)
	shadowLine("postfix", "*", days-1020)
	grp.WriteString(`root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,ubuntu
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
cdrom:x:24:ubuntu
floppy:x:25:
sudo:x:27:ubuntu
audio:x:29:
dip:x:30:ubuntu
www-data:x:33:deploy
backup:x:34:
operator:x:37:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:
plugdev:x:46:ubuntu
staff:x:50:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
systemd-timesync:x:104:
crontab:x:105:
messagebus:x:106:
syslog:x:110:
lxd:x:116:ubuntu
ubuntu:x:1000:
deploy:x:1001:
docker:x:998:deploy
redis:x:118:
postfix:x:119:
`)
	file("/etc/passwd", "root", "root", 0o644, ago(905, 3), pw.String())
	file("/etc/shadow", "root", "shadow", 0o640, ago(212, 5), sh.String())
	file("/etc/group", "root", "root", 0o644, ago(905, 3), grp.String())
	file("/etc/hostname", "root", "root", 0o644, ago(1100, 0), termHost+"\n")
	file("/etc/hosts", "root", "root", 0o644, ago(640, 2), fmt.Sprintf(`127.0.0.1 localhost
127.0.1.1 %s
%s %s.%s %s

# internal
%s %s db-prod-01
10.20.5.20 %s backup-01
10.20.6.5 jenkins.internal.%s jenkins
10.20.1.15 jump-01.internal.%s jump-01

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
`, termHost, worldHostIP, termHost, worldDomain, termHost, worldDBIP, worldDBHost, worldBackupHost, worldDomain, worldDomain))
	file("/etc/os-release", "root", "root", 0o644, ago(300, 0), `NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
`)
	file("/etc/issue", "root", "root", 0o644, ago(300, 0), "Ubuntu 20.04.6 LTS \\n \\l\n\n")
	file("/proc/version", "root", "root", 0o444, base, "Linux version 5.4.0-169-generic (buildd@lcy02-amd64-102) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2)) #187-Ubuntu SMP Thu Nov 23 14:52:28 UTC 2023\n")
	file("/etc/crontab", "root", "root", 0o644, ago(380, 6), `# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `+"`crontab'"+`
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * *	www-data	cd /var/www/connect && php artisan schedule:run >> /dev/null 2>&1
15 2	* * *	root	/opt/scripts/db-backup.sh >> /var/log/db-backup.log 2>&1
`)
	file("/etc/sudoers", "root", "root", 0o440, ago(905, 2), `#
# This file MUST be edited with the 'visudo' command as root.
#
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# User privilege specification
root	ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

#includedir /etc/sudoers.d
`)
	dir("/etc/sudoers.d", "root", "root", 0o750, ago(905, 2), true)
	file("/etc/sudoers.d/README", "root", "root", 0o440, ago(1100, 0), "#\n# As of Debian version 1.7.2p1-1, the default /etc/sudoers file created on\n# installation of the package now includes the directive:\n#\n#\t#includedir /etc/sudoers.d\n#\n")
	file("/etc/sudoers.d/deploy", "root", "root", 0o440, ago(905, 2), "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart php7.4-fpm, /usr/bin/systemctl reload nginx\n")
	file("/etc/sudoers.d/90-cloud-init-users", "root", "root", 0o440, ago(1100, 0), "# Created by cloud-init v. 23.3.3-0ubuntu0~20.04.1 on Tue, 14 Mar 2023 09:12:41 +0000\n\n# User rules for ubuntu\nubuntu ALL=(ALL) ALL\n")

	// ----- web apps -----
	dir("/var/www", "root", "root", 0o755, ago(905, 1), false)
	dir("/var/www/html", "root", "root", 0o755, ago(1100, 0), false)
	dir("/var/www/connect", "deploy", "www-data", 0o775, ago(3, 4), true)
	for _, d := range []string{"app", "bootstrap", "config", "database", "public", "resources", "routes", "storage", "tests", "vendor"} {
		dir("/var/www/connect/"+d, "deploy", "www-data", 0o775, ago(3+len(d), 4), false)
	}
	dir("/var/www/connect/.git", "deploy", "www-data", 0o775, ago(3, 4), false)
	small := func(p, content string, mt time.Time) { file(p, "deploy", "www-data", 0o664, mt, content) }
	small("/var/www/connect/artisan", "#!/usr/bin/env php\n<?php\n\ndefine('LARAVEL_START', microtime(true));\n\nrequire __DIR__.'/vendor/autoload.php';\n\n$app = require_once __DIR__.'/bootstrap/app.php';\n\n$kernel = $app->make(Illuminate\\Contracts\\Console\\Kernel::class);\n\n$status = $kernel->handle(\n    $input = new Symfony\\Component\\Console\\Input\\ArgvInput,\n    new Symfony\\Component\\Console\\Output\\ConsoleOutput\n);\n\n$kernel->terminate($input, $status);\n\nexit($status);\n", ago(700, 2))
	small("/var/www/connect/composer.json", `{
    "name": "veltrona/connect",
    "type": "project",
    "description": "Veltrona Connect customer portal",
    "license": "proprietary",
    "require": {
        "php": "^7.4",
        "fideloper/proxy": "^4.4",
        "fruitcake/laravel-cors": "^2.0",
        "guzzlehttp/guzzle": "^7.0.1",
        "laravel/framework": "^8.83",
        "laravel/sanctum": "^2.11",
        "laravel/tinker": "^2.5",
        "league/flysystem-aws-s3-v3": "~1.0",
        "barryvdh/laravel-dompdf": "^0.9.0",
        "maatwebsite/excel": "^3.1"
    },
    "require-dev": {
        "facade/ignition": "^2.5",
        "fakerphp/faker": "^1.9.1",
        "phpunit/phpunit": "^9.5.10"
    }
}
`, ago(240, 3))
	small("/var/www/connect/.env.example", "APP_NAME=Laravel\nAPP_ENV=local\nAPP_KEY=\nAPP_DEBUG=true\nAPP_URL=http://localhost\n\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=laravel\nDB_USERNAME=root\nDB_PASSWORD=\n", ago(700, 2))
	small("/var/www/connect/.gitignore", "/node_modules\n/public/hot\n/public/storage\n/storage/*.key\n/vendor\n.env\n.env.backup\n.phpunit.result.cache\nnpm-debug.log\n", ago(700, 2))
	small("/var/www/connect/server.php", "<?php\n\n$uri = urldecode(\n    parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)\n);\n\nif ($uri !== '/' && file_exists(__DIR__.'/public'.$uri)) {\n    return false;\n}\n\nrequire_once __DIR__.'/public/index.php';\n", ago(700, 2))
	small("/var/www/connect/webpack.mix.js", "const mix = require('laravel-mix');\n\nmix.js('resources/js/app.js', 'public/js')\n    .postCss('resources/css/app.css', 'public/css', []);\n", ago(700, 2))
	small("/var/www/connect/package.json", "{\n    \"private\": true,\n    \"scripts\": {\n        \"dev\": \"npm run development\",\n        \"production\": \"mix --production\"\n    },\n    \"devDependencies\": {\n        \"axios\": \"^0.21\",\n        \"laravel-mix\": \"^6.0.6\",\n        \"lodash\": \"^4.17.19\",\n        \"postcss\": \"^8.1.14\"\n    }\n}\n", ago(700, 2))
	file("/var/www/connect/.env", "deploy", "www-data", 0o640, ago(41, 7), envFile(w))

	dir("/var/www/blog", "www-data", "www-data", 0o755, ago(500, 1), false)
	file("/var/www/blog/wp-config.php", "www-data", "www-data", 0o640, ago(812, 5), wpConfig(w))

	// ----- backup script (world readable, the classic mistake) -----
	dir("/opt/scripts", "root", "root", 0o755, ago(380, 6), true)
	file("/opt/scripts/db-backup.sh", "root", "root", 0o755, ago(380, 6), backupScript(w))
	file("/opt/scripts/rotate-logs.sh", "root", "root", 0o755, ago(610, 2), "#!/bin/bash\n# keep 14 days of laravel logs\nfind /var/www/connect/storage/logs -name 'laravel-*.log' -mtime +14 -delete\nfind /var/log/nginx -name '*.gz' -mtime +30 -delete\n")
	file("/opt/scripts/README.txt", "root", "root", 0o644, ago(610, 2), "Ops scripts web-prod-03\n- db-backup.sh    nightly mysqldump -> backup-01 (cron 02:15)\n- rotate-logs.sh  log cleanup (cron.daily)\n\nQuestions: d.kessler / IT Ops\n")

	// ----- homes -----
	dir("/home/ubuntu", "ubuntu", "ubuntu", 0o750, ago(640, 3), false)
	dir("/home/deploy", "deploy", "deploy", 0o750, ago(12, 2), true)
	file("/home/deploy/.bash_logout", "deploy", "deploy", 0o644, ago(905, 2), "# ~/.bash_logout: executed by bash(1) when login shell exits.\n\nif [ \"$SHLVL\" = 1 ]; then\n    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q\nfi\n")
	file("/home/deploy/.bashrc", "deploy", "deploy", 0o644, ago(905, 2), "# ~/.bashrc: executed by bash(1) for non-login shells.\n\ncase $- in\n    *i*) ;;\n      *) return;;\nesac\n\nHISTCONTROL=ignoreboth\nshopt -s histappend\nHISTSIZE=1000\nHISTFILESIZE=2000\n\nalias ll='ls -alF'\nalias la='ls -A'\nalias dc='docker compose'\n")
	file("/home/deploy/.profile", "deploy", "deploy", 0o644, ago(905, 2), "# ~/.profile: executed by the command interpreter for login shells.\n\nif [ -n \"$BASH_VERSION\" ]; then\n    if [ -f \"$HOME/.bashrc\" ]; then\n\t. \"$HOME/.bashrc\"\n    fi\nfi\n\nif [ -d \"$HOME/bin\" ] ; then\n    PATH=\"$HOME/bin:$PATH\"\nfi\n")
	file("/home/deploy/.bash_history", "deploy", "deploy", 0o600, ago(12, 2), deployHistory())
	file("/home/deploy/deploy.sh", "deploy", "deploy", 0o755, ago(96, 3), "#!/bin/bash\nset -e\ncd /var/www/connect\ngit pull origin main\ncomposer install --no-dev --optimize-autoloader\nphp artisan migrate --force\nphp artisan config:cache\nphp artisan route:cache\nsudo systemctl restart php7.4-fpm\necho \"deployed $(git rev-parse --short HEAD)\"\n")
	dir("/home/deploy/.ssh", "deploy", "deploy", 0o700, ago(905, 2), true)
	file("/home/deploy/.ssh/id_ed25519", "deploy", "deploy", 0o600, ago(905, 2), w.Keys.DeploySSHKey)
	file("/home/deploy/.ssh/id_ed25519.pub", "deploy", "deploy", 0o644, ago(905, 2), w.Keys.DeploySSHPub+"\n")
	file("/home/deploy/.ssh/authorized_keys", "deploy", "deploy", 0o600, ago(400, 2), w.Keys.OpsSSHPub+"\n")
	file("/home/deploy/.ssh/known_hosts", "deploy", "deploy", 0o644, ago(380, 6), "|1|"+rstrSeed(w, 28)+"= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB"+rstrSeed(w, 60)+"=\n")

	dir("/root", "root", "root", 0o700, ago(2, 1), true)
	file("/root/.bashrc", "root", "root", 0o644, ago(1100, 0), "# ~/.bashrc: executed by bash(1) for non-login shells.\n\nexport LS_OPTIONS='--color=auto'\nalias ls='ls $LS_OPTIONS'\nalias ll='ls $LS_OPTIONS -l'\n")
	file("/root/.profile", "root", "root", 0o644, ago(1100, 0), "# ~/.profile: executed by Bourne-compatible login shells.\n\nif [ \"$BASH\" ]; then\n  if [ -f ~/.bashrc ]; then\n    . ~/.bashrc\n  fi\nfi\n\nmesg n 2> /dev/null || true\n")
	file("/root/.my.cnf", "root", "root", 0o600, ago(640, 4), fmt.Sprintf("[client]\nhost=%s\nuser=root\npassword=%s\n", worldDBHost, w.MySQL["root"].Password))
	file("/root/.bash_history", "root", "root", 0o600, ago(2, 1), rootHistory())
	dir("/root/.ssh", "root", "root", 0o700, ago(640, 4), true)
	file("/root/.ssh/authorized_keys", "root", "root", 0o600, ago(640, 4), w.Keys.OpsSSHPub+"\n")
	file("/root/.ssh/id_ed25519", "root", "root", 0o600, ago(640, 4), w.Keys.RootSSHKey)
	file("/root/.ssh/id_ed25519.pub", "root", "root", 0o644, ago(640, 4), w.Keys.RootSSHPub+"\n")
	dir("/root/snap", "root", "root", 0o700, ago(1000, 0), false)
	return fs
}

// rstrSeed returns stable pseudo random base64ish text derived from the world seed.
func rstrSeed(w *World, n int) string {
	const a = alnum + "+/"
	x := w.Seed | 1
	b := make([]byte, n)
	for i := range b {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = a[x%uint64(len(a))]
	}
	return string(b)
}

func envFile(w *World) string {
	k := w.Keys
	return fmt.Sprintf(`APP_NAME="Veltrona Connect"
APP_ENV=production
APP_KEY=%s
APP_DEBUG=true
APP_URL=https://connect.%s

LOG_CHANNEL=daily
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=%s
DB_PORT=3306
DB_DATABASE=%s
DB_USERNAME=connect_app
DB_PASSWORD=%s

BROADCAST_DRIVER=pusher
CACHE_DRIVER=redis
FILESYSTEM_DRIVER=s3
QUEUE_CONNECTION=redis
SESSION_DRIVER=redis
SESSION_LIFETIME=120

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.office365.com
MAIL_PORT=587
MAIL_USERNAME=%s
MAIL_PASSWORD=%s
MAIL_ENCRYPTION=tls
MAIL_FROM_ADDRESS=%s
MAIL_FROM_NAME="${APP_NAME}"

AWS_ACCESS_KEY_ID=%s
AWS_SECRET_ACCESS_KEY=%s
AWS_DEFAULT_REGION=eu-central-1
AWS_BUCKET=veltrona-connect-docs
AWS_USE_PATH_STYLE_ENDPOINT=false

PUSHER_APP_ID=1384%03d
PUSHER_APP_KEY=%s
PUSHER_APP_SECRET=%s
PUSHER_APP_CLUSTER=eu

STRIPE_KEY=pk_live_51%s
STRIPE_SECRET=%s

SAP_BRIDGE_URL=https://sap-gw.internal.%s:44300/sap/opu/odata/sap/ZVC_SHIPMENT_SRV
SAP_BRIDGE_USER=RFC_CONNECT
SAP_BRIDGE_PASSWORD=%s

SLACK_ALERT_WEBHOOK=%s
SENTRY_LARAVEL_DSN=https://%s@o41%04d.ingest.sentry.io/58%05d
JWT_SECRET=%s
`, k.AppKey, worldDomain, worldDBHost, worldAppDB, w.MySQL["connect_app"].Password, k.MailUser, k.MailPassword, k.MailUser,
		k.AWSKeyID, k.AWSSecret, w.Seed%1000, rstrSeed(w, 20), k.PusherSecret, rstrSeed(w, 40)[:34]+"Xy"+rstrSeed(w, 12),
		k.StripeSecret, worldDomain, k.SAPPassword, k.SlackWebhook, strings.ToLower(rstrSeed(w, 32)), w.Seed%10000, w.Seed%100000, k.JWTSecret)
}

func wpConfig(w *World) string {
	names := []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"}
	var keys strings.Builder
	for i, n := range names {
		v := ""
		if i < len(w.Keys.WPAuthKeys) {
			v = strings.ReplaceAll(w.Keys.WPAuthKeys[i], "'", "")
		}
		fmt.Fprintf(&keys, "define( '%s',%s'%s' );\n", n, strings.Repeat(" ", 17-len(n)), v)
	}
	return fmt.Sprintf(`<?php
/**
 * The base configuration for WordPress
 *
 * @package WordPress
 */

// ** MySQL settings ** //
/** The name of the database for WordPress */
define( 'DB_NAME', '%s' );

/** MySQL database username */
define( 'DB_USER', 'wp_blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '%s' );

/** MySQL hostname */
define( 'DB_HOST', '%s' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 */
%s
/**#@-*/

$table_prefix = 'wp_';

define( 'WP_DEBUG', false );
define( 'WP_HOME', 'https://www.%s/blog' );
define( 'WP_SITEURL', 'https://www.%s/blog' );
define( 'FS_METHOD', 'direct' );
define( 'DISALLOW_FILE_EDIT', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
`, worldWPDB, w.MySQL["wp_blog"].Password, worldDBHost, keys.String(), worldDomain, worldDomain)
}

func backupScript(w *World) string {
	return fmt.Sprintf(`#!/bin/bash
# Nightly DB backup web-prod-03 -> backup-01
# cron: 15 2 * * * (root)   last change: dk 03/2023
set -euo pipefail

DATE=$(date +%%F)
DUMPDIR=/var/backups/mysql
DBHOST=%s
DBUSER=backup
DBPASS='%s'
REMOTE=deploy@%s:/srv/backups/web-prod-03/
# TODO move to ssh key, sshpass for now (key auth broken on backup-01 since migration)
RPASS='%s'

mkdir -p "$DUMPDIR"
for DB in %s %s; do
  mysqldump -h "$DBHOST" -u "$DBUSER" -p"$DBPASS" --single-transaction --routines --triggers "$DB" | gzip > "$DUMPDIR/${DB}_${DATE}.sql.gz"
done

sshpass -p "$RPASS" rsync -az --remove-source-files "$DUMPDIR/" "$REMOTE"
find "$DUMPDIR" -type f -mtime +7 -delete
echo "$(date '+%%F %%T') backup ok"
`, worldDBHost, w.MySQL["backup"].Password, worldBackupHost, w.Unix["deploy"].Password, worldAppDB, worldWPDB)
}

func deployHistory() string {
	return `cd /var/www/connect
git status
git pull origin main
composer install --no-dev --optimize-autoloader
php artisan migrate --force
php artisan config:cache
sudo systemctl restart php7.4-fpm
tail -n 50 storage/logs/laravel-` + "2024-03-11" + `.log
docker ps
docker images
docker compose -f /srv/worker/docker-compose.yml up -d
docker logs -f connect-worker
exit
cd /var/www/connect
git log --oneline | head
./deploy.sh
ssh jenkins@10.20.6.5
sudo -l
docker run --rm -it alpine:3.18 sh
ls -la /var/backups/
exit
`
}

func rootHistory() string {
	return `apt update && apt list --upgradable
systemctl status php7.4-fpm
mysql -e "show processlist"
vim /opt/scripts/db-backup.sh
bash -x /opt/scripts/db-backup.sh
tail -f /var/log/db-backup.log
usermod -aG docker deploy
systemctl restart docker
ufw status
reboot
`
}
