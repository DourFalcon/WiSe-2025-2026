Vulnerability Report

CVE-ID: EDU-WEBLAB-2026-T02-11

Title:   Absence of Rate Limiting and Account Lockout Enabling Automated Brute-Force Authentication Bypass

Affected Lab:   DVWA — Brute Force Lab

Component:   Authentication Endpoint — DVWA Brute Force Module (`/vulnerabilities/brute/`)

Severity:   Critical

CVSS Vector:   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L

CVSS Score:   9.4

Description:  
A critical authentication vulnerability exists in the DVWA Brute Force module where the login endpoint at `/vulnerabilities/brute/` accepts unlimited, unauthenticated credential attempts without enforcing any rate limiting, account lockout, IP-based throttling, CAPTCHA, or progressive delay mechanisms. The application consistently returns HTTP 200 status codes for both successful and failed login attempts, with response body length as the sole differentiator between valid and invalid credentials, enabling reliable automated enumeration without triggering any server-side defense. An attacker requires no prior knowledge or special access to exploit this vulnerability — standard tooling such as Burp Suite Intruder or Hydra can systematically exhaust a credential wordlist against the endpoint in minutes. Successful exploitation results in full unauthorized access to protected application areas, including administrative functions, exposing all confidential data accessible to the compromised account. The sustained, high-volume request flooding characteristic of brute-force attacks also introduces measurable degradation to server responsiveness, constituting a low-level availability impact for legitimate users during the attack window.

Proof of Concept:  
```http
   Baseline login GET request captured via Burp Suite Proxy:
GET /vulnerabilities/brute/?username=admin&password=wrongpassword&Login=Login HTTP/1.1
Host: <target-ip>
Cookie: PHPSESSID=<session-id>; security=low

Failed response: HTTP 200 — Response length: ~4,901 bytes
   Contains: "Username and/or password incorrect."

Successful response: HTTP 200 — Response length: ~5,092 bytes
   Contains: "Welcome to the password protected area admin"
```
```
   Burp Suite Intruder Configuration:
   Attack Type : Cluster Bomb
   Payload Position 1 : §username§
   Payload Position 2 : §password§

Target URL:
GET /vulnerabilities/brute/?username=§admin§&password=§password§&Login=Login

Payload List — Username (Simple List):
admin
user
test
administrator

Payload List — Password (Simple List):
admin
password
test1234
123456
letmein

Differentiator: Sort responses by Length column.
   Valid credential pair produces a uniquely longer response (~5,092 bytes).
   Confirmed result: admin / password → "Welcome to the password protected area admin"
```
```bash
   Alternative — Hydra command-line brute-force (no GUI required):
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
<target-ip> http-get \
  "/vulnerabilities/brute/?username=^USER^&password=^PASS^&Login=Login" \
  -m "Cookie: PHPSESSID=<session-id>; security=low" \
  -F -V

-F: stop on first valid credential found
   -V: verbose output showing each attempt
   Successful result output:
   [80][http-get] host: <target-ip>   login: admin   password: password
```

Steps to Reproduce:

1. Log in to the DVWA application at `http://<target-ip>/login.php` using any valid credentials, navigate to   DVWA Security  , and confirm the Security Level is set to   Low  .
2. Navigate to the Brute Force module at `http://<target-ip>/vulnerabilities/brute/` and submit any login attempt (e.g., `username=admin&password=wrongpassword`) to generate a capturable HTTP request.
3. Open Burp Suite, ensure the browser is proxied through it, and intercept the login GET request at `/vulnerabilities/brute/`; confirm the full request including `PHPSESSID` cookie is captured in the HTTP History tab.
4. Right-click the captured request and select   Send to Intruder  . In the Intruder   Positions   tab, clear all default markers, then highlight the `username` value and click   Add §  , then highlight the `password` value and click   Add §  . Set the attack type to   Cluster Bomb  .
5. In the   Payloads   tab, configure Payload Set 1 (username) with a simple list: `admin, user, test, administrator`. Configure Payload Set 2 (password) with a simple list: `admin, password, test1234, 123456, letmein`.
6. Click   Start Attack   and observe that the server returns   HTTP 200   for every attempt — confirming zero lockout, zero CAPTCHA, and zero rate-limiting enforcement across all requests.
7. In the Intruder results window, sort by the   Length   column and identify the response with a distinctly different byte count — this entry corresponds to the valid credential pair (e.g., `admin` / `password`, response ~5,092 bytes containing "Welcome to the password protected area admin").
8. Verify that no lockout or delay was triggered at any point during the attack by reviewing the full results list — confirm all other responses returned identical lengths corresponding to the failure message.
9. Navigate to `http://<target-ip>/vulnerabilities/brute/?username=admin&password=password&Login=Login` in the browser and confirm successful unauthorized access to the protected area using the brute-forced credentials, demonstrating complete authentication bypass.

Remediation:

1.   Enforce account lockout after repeated failed attempts:   Temporarily lock an account (e.g., 15–30 minutes) after a configurable threshold of consecutive failed login attempts (e.g., 5 attempts). Implement exponential backoff for repeated failures to deter sustained automated attacks while minimizing impact on legitimate users.
2.   Implement IP-based rate limiting on the authentication endpoint:   Restrict the number of login requests accepted from a single IP address within a defined time window (e.g., maximum 5 attempts per minute per IP). Return `HTTP 429 Too Many Requests` with a `Retry-After` header for requests exceeding the threshold.
3.   Migrate the login operation from GET to POST:   Credential parameters (`username`, `password`) must never be transmitted via GET requests, as they are logged in server access logs, browser history, and proxy caches. Enforce HTTP POST for all authentication actions and reject GET-based login attempts server-side.
4.   Implement CAPTCHA or proof-of-work challenges after failed attempts:   Present a CAPTCHA challenge (e.g., reCAPTCHA v3) after 3 consecutive failed login attempts from the same session or IP, requiring human verification before further attempts are accepted.
5.   Require Multi-Factor Authentication (MFA) for privileged accounts:   Enforce TOTP-based or hardware-token MFA for administrative and elevated-privilege accounts, ensuring that a brute-forced password alone is insufficient to achieve unauthorized access.
6.   Return generic, non-informational error messages:   Replace specific failure messages with a single unified response (e.g., "Invalid username or password.") and ensure response body length and timing are consistent for both failed username and failed password scenarios, eliminating the length-based differentiator used for automated enumeration.
7.   Deploy a Web Application Firewall (WAF) with brute-force detection rules:   Configure WAF rules (e.g., ModSecurity with OWASP CRS) to detect and automatically block or challenge sources generating high volumes of authentication requests, including User-Agent patterns associated with automated tooling (Burp Suite, Hydra, Medusa).
8.   Implement centralized authentication logging and real-time alerting:   Log all authentication attempts with timestamp, source IP, username, and outcome. Configure automated alerts for anomalous patterns such as more than 10 failed attempts within 60 seconds from a single IP, enabling Security Operations teams to respond to brute-force campaigns before credentials are compromised.

Discovered By:   Team 2

Date:   March 7, 2026

