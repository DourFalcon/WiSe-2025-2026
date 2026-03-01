Vulnerability Report

CVE-ID: EDU-WEBLAB-2026-TEAM2-008

Title:   Unauthorized Account Impersonation via JWT "Algorithm None" Signature Bypass Leading to Authentication Circumvention

Affected Lab:   token-tower

Component:   JSON Web Token (JWT) Authentication Mechanism — Signature Validation Logic

Severity:   Critical

CVSS Vector:   CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

CVSS Score:   9.9

Description:  
A critical authentication bypass vulnerability was identified in the token-tower machine, where the application's JWT validation logic fails to reject tokens that specify `"alg": "none"` in the header — a well-documented attack technique in which the signature portion of the token is completely removed and the server is instructed to accept the unsigned payload as trusted. The vulnerability exists because the server does not enforce a strict allowlist of permitted signing algorithms, nor does it mandate that a valid cryptographic signature be present before processing JWT claims. An attacker with only a low-privileged guest account can capture their issued token, manipulate the header to specify the `none` algorithm, modify the payload to assume any arbitrary user identity by altering the `id`, `user`, and `role` fields, strip the signature entirely, and present the resulting unsigned token to the server — which accepts it without challenge. This was demonstrated by successfully impersonating a separate user account (`id: 3`) without possessing that user's credentials or session. The complete absence of signature enforcement renders the entire JWT-based authentication system ineffective, allowing unrestricted horizontal account takeover across all user identities present in the application.

Proof of Concept:  
```bash
   Original JWT token captured from guest user authentication response:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlciI6Imd1ZXN0Iiwicm9sZSI6Imd1ZXN0In0.<valid_signature>

Step 1 — Decoded original header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Step 2 — Decoded original payload:
{
  "id": 2,
  "user": "guest",
  "role": "guest"
}

Step 3 — Modified header (algorithm set to none):
{
  "alg": "none",
  "typ": "JWT"
}

Step 4 — Modified payload (impersonating user with id 3):
{
  "id": 3,
  "user": "user",
  "role": "user"
}

Step 5 — Forged unsigned token structure (signature segment removed, trailing dot retained):
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MywidXNlciI6InVzZXIiLCJyb2xlIjoidXNlciJ9.

Step 6 — Replace the Authorization header in Burp Suite with the forged unsigned token:
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MywidXNlciI6InVzZXIiLCJyb2xlIjoidXNlciJ9.
```

Steps to Reproduce:  
1. Navigate to the token-tower machine's login page and authenticate using the guest user credentials to obtain a valid low-privileged JWT session token.
2. In Burp Suite, intercept the server's authentication response and extract the full JWT token issued to the guest user from the `Authorization` header or response body.
3. Paste the captured token into a JWT debugger (e.g., jwt.io) and examine the decoded header, confirming the original signing algorithm is `HS256`.
4. Modify the `"alg"` field in the JWT header from `"HS256"` to `"none"`, instructing the server to process the token without verifying any cryptographic signature.
5. In the JWT payload section, change the `"id"` field to `3`, the `"user"` field to `"user"`, and the `"role"` field to `"user"` to impersonate the target account.
6. Remove the signature portion of the token entirely, retaining the trailing dot after the payload segment to preserve valid JWT formatting (format: `header.payload.`).
7. Copy the resulting unsigned, manipulated token from the JWT debugger.
8. In Burp Suite, intercept an outbound authenticated request to the application and replace the original JWT in the `Authorization` header with the forged unsigned token.
9. Forward the modified request to the server and observe that the server accepts the unsigned token without returning an authentication error or signature validation failure.
10. Confirm successful impersonation of the target user account (`id: 3`) by verifying that the application responds with data and access privileges belonging to the impersonated user, demonstrating complete authentication bypass without possessing that user's credentials.

Remediation:  
1.   Explicitly reject the `"alg": "none"` algorithm at the JWT validation layer   — the server must maintain a strict server-side allowlist of accepted signing algorithms (e.g., `["HS256", "RS256"]`) and immediately reject any token whose header specifies `"none"`, an empty string, or any algorithm outside the allowlist, regardless of what the token header claims.
2.   Enforce mandatory signature validation on every JWT processed by the server   — the validation logic must never branch into a code path that skips signature verification; tokens lacking a valid, non-empty signature must be categorically rejected with a `401 Unauthorized` response before any claims are read or acted upon.
3.   Migrate to asymmetric signing algorithms (RS256 or ES256)   — using public/private key pair signing eliminates entire classes of symmetric secret attacks and makes algorithm confusion attacks significantly harder to execute; the server verifies tokens using only the public key, which cannot be used to forge new tokens.
4.   Implement server-side identity and role validation independent of JWT claims   — the `id`, `user`, and `role` values extracted from the JWT payload must be cross-referenced against the authoritative database on every privileged request, ensuring that tampered claims cannot grant access that does not correspond to a legitimate server-side record.
5.   Use a well-maintained, security-audited JWT library rather than custom validation logic   — libraries such as `python-jose`, `jsonwebtoken` (Node.js with explicit `algorithms` parameter), or `java-jwt` with configured algorithm constraints handle algorithm confusion protections by default when configured correctly; avoid implementing JWT parsing from scratch.
6.   Enforce short token expiration windows and implement token revocation   — limit JWT validity to short durations (e.g., 15 minutes) and maintain a server-side blocklist or session store to allow immediate invalidation of tokens upon logout or detected anomaly, limiting the usability window of any captured or forged token.
7.   Log and alert on all JWT validation failures   — any token rejected due to an invalid signature, unrecognized algorithm, or malformed structure should generate a security event log entry including the source IP, timestamp, and raw token header; repeated failures from a single source should trigger automated alerting as a potential attack indicator.
8.   Conduct a full audit of all JWT consumption points across the application   — verify that every endpoint that accepts a JWT applies the same strict validation pipeline; partial or inconsistent enforcement (where some routes validate signatures and others do not) creates exploitable gaps that attackers can target selectively.

Discovered By:   Team 2

Date:   February 28, 2026

