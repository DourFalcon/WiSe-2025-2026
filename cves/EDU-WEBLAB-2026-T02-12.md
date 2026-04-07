Vulnerability Report

CVE-ID: EDU-WEBLAB-2026-T02-12

Title:   Insecure CAPTCHA Implementation Allowing Password Change Without Valid Human Verification

Affected Lab:   DVWA — Insecure CAPTCHA Lab

Component:   Password-Change Endpoint — DVWA Insecure CAPTCHA Module (`/vulnerabilities/captcha/`)

Severity:   High

CVSS Vector:   CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

CVSS Score:   8.8

Description:  
A high-severity insecure CAPTCHA vulnerability exists in the password-change functionality of the DVWA Insecure CAPTCHA module, where the application's two-step password-change workflow fails to enforce server-side verification of CAPTCHA completion before executing the credential update. The vulnerable endpoint exposes a `step` parameter that controls the workflow stage, allowing an attacker to bypass the CAPTCHA verification phase entirely by directly submitting a crafted POST request with `step=2`, which the server processes and accepts as a legitimately CAPTCHA-verified request. Because the CAPTCHA challenge result is never bound to a server-side session token or cryptographically validated, any attacker capable of intercepting and modifying a single HTTP request — or crafting one from scratch — can change any authenticated user's password without solving any human verification challenge. Successful exploitation results in full unauthorized account takeover, granting the attacker complete access to all data and functions accessible to the compromised account. The locked-out legitimate user experiences complete loss of account availability, and the confidentiality and integrity of all account-associated data is fully compromised, making this a high-severity vulnerability requiring immediate remediation.

Proof of Concept:  
```http
   Step 1 — Original two-step flow intercepted via Burp Suite Proxy.
   Legitimate Step 1 request (CAPTCHA presented to user):
POST /vulnerabilities/captcha/ HTTP/1.1
Host: <target-ip>
Cookie: PHPSESSID=<session-id>; security=low
Content-Type: application/x-www-form-urlencoded

step=1&password_new=hacked123&password_conf=hacked123&captcha=<user-solved-value>&Change=Change
```
```http
   Step 2 — CAPTCHA bypass: skip step=1 entirely and submit step=2 directly.
   The server processes this as a fully verified password-change request
   with NO CAPTCHA validation performed.
POST /vulnerabilities/captcha/ HTTP/1.1
Host: <target-ip>
Cookie: PHPSESSID=<session-id>; security=low
Content-Type: application/x-www-form-urlencoded

step=2&password_new=hacked123&password_conf=hacked123&Change=Change

Server response confirms unauthorized password change:
   "Password Changed."
```
```bash
   Automated exploitation via curl — no browser or CAPTCHA solving required:
curl -X POST "http://<target-ip>/vulnerabilities/captcha/" \
  -H "Cookie: PHPSESSID=<session-id>; security=low" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "step=2&password_new=hacked123&password_conf=hacked123&Change=Change"

Expected response body contains:
   "Password Changed."

Post-exploitation verification:
   Username: admin
   Password: hacked123
   → Successful login confirms unauthorized credential modification.
```

Steps to Reproduce:

1. Log in to the DVWA application at `http://<target-ip>/login.php` using valid credentials (e.g., `admin` / `password`), navigate to   DVWA Security  , and confirm the Security Level is set to   Low  .
2. Navigate to the Insecure CAPTCHA module at `http://<target-ip>/vulnerabilities/captcha/` and observe the two-field password-change form with an embedded CAPTCHA challenge.
3. Open Burp Suite and enable proxy interception. Fill in the password fields with any values and click   Change   — do not solve the CAPTCHA — and capture the resulting POST request in Burp Suite's Intercept tab.
4. Examine the intercepted request body and identify the `step` parameter, which will be set to `step=1` for the initial CAPTCHA-verification phase. Confirm the CAPTCHA value is transmitted as a plain, user-supplied parameter with no server-side token binding.
5. In Burp Suite's Intercept tab, modify the request body by changing `step=1` to `step=2` and removing the CAPTCHA parameter entirely, leaving only: `step=2&password_new=hacked123&password_conf=hacked123&Change=Change`.
6. Forward the modified request to the server and observe that the application returns   "Password Changed."   — confirming the server accepted the request as CAPTCHA-verified despite no CAPTCHA challenge being solved.
7. To confirm the attack is fully automatable without any proxy interaction, execute the curl command from the Proof of Concept section directly from the attacker's terminal and verify the same   "Password Changed."   response is returned programmatically.
8. Log out of the DVWA application completely, then attempt to log back in using the original credentials (`admin` / `password`) — confirm authentication fails, demonstrating the password was successfully overwritten without CAPTCHA verification.
9. Log in using the attacker-set credentials (`admin` / `hacked123`) to confirm full unauthorized account takeover, and verify that the step-based workflow bypass represents a complete failure of the CAPTCHA control as a security mechanism.

Remediation:

1.   Enforce server-side CAPTCHA validation before processing any password change:   The server must independently verify CAPTCHA completion against a server-generated, session-bound challenge token before executing any state-changing operation. Never trust a client-supplied `step` parameter to indicate that CAPTCHA verification has already occurred.
2.   Bind CAPTCHA tokens to the authenticated user session:   Generate a unique, cryptographically random CAPTCHA token per session and per request, store it server-side, and validate it on every form submission. Invalidate and regenerate the token immediately after use to prevent replay attacks.
3.   Eliminate the client-controlled `step` parameter from the workflow:   The multi-step workflow state must be tracked exclusively server-side (e.g., via session variables). Allowing the client to supply a `step` value that bypasses verification stages is an architectural flaw; remove all such parameters from client-facing requests.
4.   Reject any password-change request that does not include a valid, server-verified CAPTCHA response:   Return `HTTP 403 Forbidden` for requests where the CAPTCHA parameter is absent, expired, already used, or does not match the server-stored challenge. Log all such rejected attempts as potential automation or abuse indicators.
5.   Implement a modern, server-verified CAPTCHA solution such as Google reCAPTCHA v2/v3:   Replace any self-implemented CAPTCHA with a third-party service that performs server-side token verification via a secure back-channel API call (e.g., `https://www.google.com/recaptcha/api/siteverify`), ensuring the verification cannot be bypassed by client-side parameter manipulation.
6.   Require re-authentication (current password confirmation) before processing credential changes:   Force the user to supply their existing password as part of the password-change request. This defense-in-depth measure ensures that even a complete CAPTCHA bypass cannot succeed without possession of the current credential.
7.   Implement the `SameSite=Strict` cookie attribute and enforce POST-only credential operations:   Configure session cookies with `SameSite=Strict` to prevent cross-site request forgery chaining with this vulnerability. Ensure the password-change endpoint only accepts POST requests and rejects GET-based or cross-origin submissions server-side.
8.   Log and alert on all password-change attempts, including rejected requests:   Record every password-change attempt with timestamp, source IP, session identifier, CAPTCHA verification outcome, and success or failure status. Configure real-time alerts for patterns indicative of automated bypass attempts, such as multiple password-change requests within a short time window or requests with missing CAPTCHA parameters.

Discovered By:   Team 2

Date:   March 7, 2026

