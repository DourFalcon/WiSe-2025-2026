CVE-ID: EDU-WEBLAB-2026-TEAM2-023

Title: JWT Authentication Bypass via "none" Algorithm Enabling Privilege Escalation and Unauthorized Access

Affected Lab: JWT Authentication Module

Component: Token verification and signature validation logic

Severity: Critical

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

CVSS Score: 9.1

Description:
A critical authentication bypass vulnerability exists in the JWT Authentication module due to a failure in the signature verification logic. The application’s JWT library is configured to trust the alg (algorithm) header provided within the token itself without verifying it against a server-side allowlist. An attacker can exploit this by intercepting a legitimate JSON Web Token and modifying the header to specify the none algorithm. By stripping the signature from the token and optionally modifying the payload (e.g., changing the user role to admin), an adversary can submit an unsigned, yet "valid" token to the server. The backend incorrectly accepts this unsigned token as authentic, leading to a complete bypass of authentication mechanisms. This allows an unauthenticated attacker to impersonate any user, escalate privileges to administrative levels, and access sensitive system flags or restricted endpoints.

Proof of Concept:

JavaScript
/* --- PAYLOAD 1: Header Modification --- */
/* Decode the JWT header and change the algorithm to 'none' */

{
  "alg": "none",
  "typ": "JWT"
}

/* --- PAYLOAD 2: Payload Manipulation --- */
/* Modify the 'role' or 'user' claims to escalate privileges */

{
  "user": "admin",
  "role": "administrator",
  "iat": 1712521839
}

/* --- PAYLOAD 3: Final Crafted Token --- */
/* Re-encode [Header].[Payload]. with an empty signature (trailing dot) */

eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciIsImlhdCI6MTcxMjUyMTgzOX0.

/* Result: Accessing /api/admin returns sensitive flags:
   WEBSPLOIT{PRIVL3G3_3SC4L4TI0N}
   WEBSPLOIT{JWT_N0N3_ALG0RITHM_BYPASS}
   WEBSPLOIT{JWT_M4ST3R_HACK3R} */

Steps to Reproduce:

Access the application and perform a standard login to receive a valid JSON Web Token (JWT) in the response or cookie.
Intercept a request to a protected endpoint (e.g., /api/user/profile) using a proxy tool like Burp Suite.
Decode the Token: Use a tool (e.g., jwt.io) to decode the Base64URL encoded header and payload segments.
Modify the Algorithm: Change the alg value in the header from its original value (e.g., HS256) to none.
Manipulate Payload (Optional): Update the role, uid, or username fields in the payload to target an administrative account.
Construct Unsigned Token: Re-encode the header and payload. Concatenate them with a period (.) and ensure the final token ends with a trailing period, representing an empty signature.
Submit the Payload: Replace the legitimate token in the Authorization: Bearer <token> header with the crafted "none" algorithm token.
Verify Bypass: Send the request to a restricted administrative endpoint (e.g., /dashboard or /admin/settings).
Confirm Privilege Escalation: Observe that the server processes the request successfully and returns data restricted to the administrative role, bypassing all signature checks.
Capture and document the system flags returned in the response to confirm the "Critical" severity and complete compromise of the authentication handler.

Remediation:

Explicitly Reject the "none" Algorithm: Configure the JWT validation logic to throw an error if the alg header is set to none. Most modern libraries have a specific configuration or flag to disable this insecure feature.
Enforce Strict Signature Verification: Ensure that the verify() method is always called with a defined, server-side secret or public key. Never allow the library to determine the validation path based solely on the token's header.
Validate Algorithm against an Allowlist: Define an explicit set of permitted algorithms (e.g., ['HS256'] or ['RS256']) during the verification process. Any token using an algorithm outside of this list should be rejected immediately.
Use Updated Security Libraries: Ensure that the JWT library being used (e.g., jsonwebtoken, jose, PyJWT) is updated to a version where "none" algorithm support is disabled by default.
Implement Server-Side Privilege Checks: Do not rely solely on the JWT payload for authorization. Cross-reference the user ID in the token with a secure backend database to verify the user's current roles and permissions.
Apply Token Expiration (exp): Ensure all tokens include a short-lived exp claim to limit the window of opportunity for token manipulation or replay attacks.
Secure Key Management: Ensure that signing keys (HS256 secrets or RS256 private keys) are stored securely in environment variables or a Key Management Service (KMS), and are rotated regularly.
Logging and Alerting: Log all authentication failures, specifically those related to "Algorithm Mismatch" or "Invalid Signature," and set up alerts for multiple failed attempts from a single IP address.

Discovered By: Team 2

Date: March 21, 2026
