Vulnerability Report

CVE-ID: EDU-WEBLAB-2026-TEAM2-007

Title:   Weak JWT Secret Key Enables Token Forgery and Privilege Escalation to Administrator via Parameter Tampering

Affected Lab:   token-tower

Component:   JSON Web Token (JWT) Authentication and Authorization Mechanism

Severity:   Critical

CVSS Vector:   CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

CVSS Score:   9.9

Description:  
A critical authentication and privilege escalation vulnerability was identified in the token-tower machine, where the application issues JSON Web Tokens signed with a cryptographically weak secret key that is susceptible to offline brute-force attacks using tools such as Hashcat. Because the application relies solely on the JWT payload to determine user identity and role — without performing independent server-side privilege validation — an attacker who recovers the signing secret can craft an arbitrarily forged token with elevated claims, such as `"role": "admin"` and `"id": 1`, and have it fully accepted by the server. The attack chain requires only a low-privileged guest account to obtain a valid token for cracking, after which the forged token grants complete administrative access with no further barriers. The combination of a guessable signing secret and the absence of server-side authorization checks constitutes a critical security failure, as it allows any authenticated user to escalate their privileges to administrator unilaterally. Successful exploitation results in full compromise of confidentiality, integrity, and availability of the application and all data accessible to the administrative role.

Proof of Concept:  
```bash
   Step 1 — Extract the JWT token from the captured Burp Suite response (example token):
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlciI6Imd1ZXN0Iiwicm9sZSI6Imd1ZXN0In0.<signature>

Step 2 — Save the JWT token to a file for offline cracking:
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwidXNlciI6Imd1ZXN0Iiwicm9sZSI6Imd1ZXN0In0.<signature>" > jwt.txt

Step 3 — Crack the JWT signing secret using Hashcat (mode 16500 = JWT):
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

Step 4 — Hashcat recovers the weak secret key (example output):
   <token>:<cracked_secret>
   e.g.: eyJ....<signature>:secret123

Step 5 — Forge a new JWT token with admin privileges using the recovered secret.
   Original guest payload:
{
  "id": 2,
  "user": "guest",
  "role": "guest"
}

Forged admin payload (modified in JWT debugger, re-signed with cracked secret):
{
  "id": 1,
  "user": "admin",
  "role": "admin"
}

Step 6 — Replace the Authorization header in Burp Suite with the forged token:
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.<forged_admin_payload>.<new_signature>
```

Steps to Reproduce:  
1. Navigate to the token-tower machine's login page and authenticate using the guest user credentials to obtain a valid low-privileged session.
2. In Burp Suite, intercept the server's authentication response and extract the JWT token issued to the guest user from the `Authorization` header or response body.
3. Save the captured JWT token to a local file (e.g., `jwt.txt`) on the Kali Linux machine in preparation for offline cracking.
4. Run Hashcat against the token using JWT cracking mode (`-m 16500`) with a standard wordlist such as `rockyou.txt`: `hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt`
5. Observe that Hashcat successfully recovers the weak signing secret appended to the cracked token in the output (e.g., `secret123`), confirming the secret is brute-forceable.
6. Log back in as the guest user and capture the freshly issued JWT token from the response in Burp Suite.
7. Open a JWT debugger tool (e.g., jwt.io) and paste the captured token; modify the payload by changing `"id"` to `1`, `"user"` to `"admin"`, and `"role"` to `"admin"`.
8. Enter the recovered secret key in the signature verification field of the JWT debugger to re-sign the forged token, generating a valid signature for the tampered payload.
9. In Burp Suite, intercept a request to a privileged endpoint and replace the original JWT in the `Authorization` header with the newly forged admin token.
10. Forward the modified request and observe that the server accepts the forged token without rejection, granting full administrative access and confirming successful privilege escalation.

Remediation:  
1.   Replace the weak JWT signing secret with a cryptographically strong, randomly generated key   — the secret must be at minimum 256 bits (32 bytes) of high-entropy random data generated using a cryptographically secure pseudorandom number generator (CSPRNG); hardcoded or dictionary-based secrets must never be used.
2.   Enforce strict server-side role and permission validation independent of JWT claims   — the server must never trust the `role`, `id`, or `user` fields from the JWT payload as the sole source of authorization truth; every privileged operation must be re-validated against the authoritative database record for the authenticated user's actual permissions.
3.   Consider migrating to asymmetric JWT signing algorithms (RS256 or ES256)   — using a public/private key pair eliminates the risk of secret key brute-forcing entirely, as the private key is never transmitted or exposed to clients, and compromise of the public key does not allow token forgery.
4.   Implement JWT expiration (`exp`) and issuance time (`iat`) claims with short token lifetimes   — limiting token validity windows (e.g., 15 minutes) reduces the window of opportunity for an attacker to crack and exploit a captured token; pair this with refresh token rotation to maintain usability.
5.   Maintain a server-side token revocation mechanism or token binding   — implement a token blocklist or session store so that issued tokens can be invalidated immediately upon logout or detected compromise, preventing replay of cracked tokens.
6.   Validate the full JWT structure and claims on every request   — the server must verify the algorithm header matches the expected algorithm (reject `"alg": "none"` attacks), validate the signature cryptographically, and confirm all required claims (`exp`, `iat`, `sub`) are present and within acceptable bounds.
7.   Deploy runtime alerting for JWT-related anomalies   — log and alert on events such as tokens with unrecognized signatures, requests containing tokens with modified payloads, repeated authentication attempts, or privilege claim mismatches between the token and the database record.
8.   Conduct regular secret rotation and secrets management hygiene   — store JWT signing secrets in a dedicated secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager) rather than in source code or configuration files, and implement a rotation policy to periodically replace signing secrets without service disruption.

Discovered By:   Team 2

Date:   February 26, 2026

