CVE-ID: EDU-WEBLAB-2026-TEAM2-003

Title:   SQL Injection in Login Functionality Enabling Complete Authentication Bypass

Affected Lab:   sqli-breach

Component:   Login Functionality - Username Input Field

Severity:   Critical

CVSS Vector:   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

CVSS Score:   10.0

Description:
A critical SQL injection vulnerability exists in the login functionality of the sqli-breach machine, allowing complete authentication bypass without valid credentials. The application fails to sanitize user input in the username field before incorporating it into SQL queries, enabling attackers to manipulate the query logic using SQL comment sequences. By injecting the payload `admin' --`, attackers can prematurely terminate the WHERE clause and comment out password verification, forcing the database to authenticate as any user (typically admin) without knowing the password. This grants immediate unauthorized access with full administrative privileges, compromising the confidentiality, integrity, and availability of the entire application and its data.

Proof of Concept:
sql
# Authentication bypass payload in username field:
admin' --

Alternative payloads that achieve the same result:
admin'#
administrator' --
' OR '1'='1' --
admin' OR 1=1 --

Steps to Reproduce:
1. Navigate to the login page of the sqli-breach machine using a web browser
2. Locate the username and password input fields on the authentication form
     <img width="939" height="393" alt="image" src="https://github.com/user-attachments/assets/df105169-33c3-4df8-adea-9b9040a3a25c" />

4. In the username field, enter the SQL injection payload: `admin' --` (note the space after the double dash)
5. Leave the password field empty or enter any arbitrary value (e.g., "test" or "password")
6. Click the login button or press Enter to submit the authentication request
7. Observe that the application successfully authenticates and grants access without validating the password
8. Verify that you have been logged in as the admin user by checking the session information, username display, or accessing admin-only functionality
9. Confirm that the SQL injection manipulated the backend query by commenting out the password verification clause
10. Test alternative payloads such as `admin'#` or `' OR '1'='1' --` to verify multiple injection vectors
    <img width="939" height="429" alt="image" src="https://github.com/user-attachments/assets/7df23070-88a6-4374-8cbd-9ae60735fa25" />

12. Access administrative panels, user data, or sensitive functionality to confirm complete system compromise with elevated privileges

Remediation:
1. Immediately implement parameterized queries (prepared statements) for all database operations, ensuring user input is never directly concatenated into SQL statements
2. Use Object-Relational Mapping (ORM) frameworks that automatically handle query parameterization and prevent SQL injection by design
3. Implement strict server-side input validation using allowlists for username formats (e.g., alphanumeric characters only) and reject any input containing SQL metacharacters such as quotes, semicolons, or comment sequences
4. Apply the principle of least privilege to database accounts used by the application, ensuring they cannot access, modify, or delete data beyond their required scope
5. Implement additional authentication controls such as multi-factor authentication (MFA), account lockout policies, and CAPTCHA to add defense-in-depth layers
6. Deploy a Web Application Firewall (WAF) configured to detect and block common SQL injection patterns and authentication bypass attempts
7. Implement comprehensive logging and monitoring for failed login attempts, unusual authentication patterns, and SQL error messages that could indicate injection attempts
8. Conduct a thorough code review and security assessment of all database interaction points throughout the application to identify and remediate similar SQL injection vulnerabilities

Discovered By:   Team 2

Date:   February 8, 2026
