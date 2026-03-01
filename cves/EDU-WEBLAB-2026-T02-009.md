Vulnerability Report

CVE-ID: EDU-WEBLAB-2026-TEAM2-009

Title:   Path Traversal Vulnerability Enables Unauthorized Access to Sensitive System Files via Directory Sequence Injection

Affected Lab:   maze-walker

Component:   File Retrieval Functionality — User-Controlled File Path Input Parameter

Severity:   High

CVSS Vector:   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

CVSS Score:   7.5

Description:  
A high-severity path traversal vulnerability was identified in the maze-walker machine, where the application fails to validate or sanitize user-supplied file path input, allowing an unauthenticated attacker to escape the intended web root directory by injecting `../` directory traversal sequences into the file path parameter. The vulnerability exists because the application constructs file system paths by directly concatenating user-controlled input without enforcing boundaries that restrict access to a designated safe directory, enabling arbitrary navigation of the underlying server file system. This was successfully exploited to read the contents of `/etc/passwd` — a sensitive system file containing user account information including usernames, user IDs, group IDs, and home directory paths for all accounts on the system. While `/etc/passwd` does not contain password hashes in modern Linux configurations, its disclosure provides an attacker with a detailed map of system user accounts that can be leveraged to identify further attack targets, facilitate privilege escalation, or support brute-force and social engineering efforts. The absence of both input validation and operating system-level directory restrictions makes this vulnerability exploitable remotely by any unauthenticated user with access to the web interface.

Proof of Concept:  
```bash
   Basic path traversal payload to access /etc/passwd:
   Injected via the vulnerable file path parameter in the URL or request body

Standard traversal (adjust depth based on web root location):
../../../../etc/passwd

URL-encoded variant to bypass basic input filters:
..%2F..%2F..%2F..%2Fetc%2Fpasswd

Double URL-encoded variant to bypass secondary filters:
..%252F..%252F..%252F..%252Fetc%252Fpasswd

Example vulnerable URL structure:
http://<maze-walker-ip>/download?file=../../../../etc/passwd

Example /etc/passwd output confirming successful exploitation:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

Steps to Reproduce:  
1. Navigate to the maze-walker machine's web interface and identify the functionality that accepts a file name or file path as a user-supplied input parameter (e.g., a file download, file viewer, or document retrieval feature).
2. Submit a normal, expected file name through the identified functionality and observe the application's standard behavior to confirm the file retrieval mechanism is active.
3. Intercept the request using Burp Suite or observe the URL structure to identify the exact parameter name used to specify the file path (e.g., `?file=`, `?path=`, `?page=`).
4. Modify the file path parameter by injecting a basic path traversal sequence, replacing the original value with `../../../../etc/passwd` to attempt to navigate from the web root up to the system root and access the target file.
5. Submit the modified request and observe the application's response to determine whether the traversal sequence is processed or blocked.
6. If the initial payload is filtered, attempt URL-encoded variants such as `..%2F..%2F..%2F..%2Fetc%2Fpasswd` or double-encoded variants such as `..%252F..%252F..%252F..%252Fetc%252Fpasswd` to bypass basic input sanitization.
7. Confirm successful path traversal by observing that the contents of `/etc/passwd` are returned in the server's response, displaying the list of system user accounts.
8. Verify the full impact by noting that the disclosed account information — including usernames, UIDs, GIDs, and home directories — was retrieved without any authentication or authorization, confirming unrestricted read access to the server's file system beyond the intended web directory.

Remediation:  
1.   Implement strict allow-list-based input validation on all file path parameters   — define the exact set of permitted file names or paths the application is allowed to serve, and reject any input that does not match the allowlist precisely; never attempt to sanitize path traversal sequences reactively, as filter bypass techniques are well-documented and numerous.
2.   Resolve and canonicalize file paths server-side before processing   — use language-native path resolution functions (e.g., `realpath()` in PHP, `os.path.realpath()` in Python, `Path.toRealPath()` in Java) to resolve the full absolute path of any user-supplied input, then verify that the resolved path begins with the expected base directory string before any file operation is performed.
3.   Enforce a strict jail or chroot environment for the web application's file access scope   — configure the web server and application runtime to operate within a chroot jail or use OS-level controls to ensure the application process is physically incapable of accessing files outside the designated web root or content directory, regardless of the path supplied.
4.   Block and strip traversal sequences at the application and web server level   — configure the web server (e.g., Apache, Nginx) and application middleware to detect and reject requests containing `../`, `..\`, URL-encoded equivalents (`%2F`, `%5C`), and double-encoded equivalents (`%252F`) as an additional defense-in-depth layer, while ensuring this does not substitute for proper canonicalization.
5.   Apply the principle of least privilege to the web application process   — ensure the web server and application run under a dedicated low-privileged service account (e.g., `www-data`) with read permissions scoped exclusively to the directories required for normal operation; the application account must not have read access to sensitive system files such as `/etc/passwd`, `/etc/shadow`, or application configuration files outside the web root.
6.   Conduct an audit of all file handling operations across the application   — review every location in the codebase where user input influences file system operations (open, read, include, require, download) and apply consistent canonicalization and boundary enforcement; a single unprotected file path parameter is sufficient for full exploitation.
7.   Implement logging and alerting for path traversal indicators   — monitor web server and application logs for requests containing `../`, encoded traversal sequences, or attempts to access known sensitive paths (e.g., `/etc/passwd`, `/etc/shadow`, `/proc/`); configure automated alerting to notify the security team upon detection of such patterns.

Discovered By:   Team 2

Date:   February 28, 2026
