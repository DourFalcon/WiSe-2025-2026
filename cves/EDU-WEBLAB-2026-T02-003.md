CVE-ID: EDU-WEBLAB-2026-T02-003

Title:    Unauthenticated Access to Grafana Dashboard Exposing Sensitive Monitoring Data

Affected Lab:    y-wing

Component:    Grafana Web Interface — Anonymous Authentication Configuration

Severity:    High

CVSS Vector:    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

CVSS Score:    7.5

Description:
A high-severity unauthenticated access vulnerability was identified in the Grafana monitoring dashboard hosted on the y-wing machine. The vulnerability exists due to Grafana's anonymous access feature being enabled in its configuration (`auth.anonymous.enabled = true`), which allows any unauthenticated user to access the dashboard interface without providing valid credentials. This misconfiguration exposes sensitive infrastructure metrics, system performance data, internal network topology, and service health information to any attacker who can reach the Grafana port, requiring no authentication or prior knowledge of the system. An attacker can leverage the disclosed data — including host names, IP addresses, service states, and query data — to perform reconnaissance and facilitate further targeted attacks against the environment. The absence of any access control on a monitoring interface of this nature represents a significant security risk in both confidentiality and operational exposure.

Proof of Concept: bash

Step 1: Discover Grafana service running on default or non-standard port
nmap -sV -p 3000 <target-ip>

Step 2: Access Grafana dashboard directly in browser with no credentials
http://<target-ip>:3000

Step 3: Confirm anonymous access by navigating to dashboards without logging in
http://<target-ip>:3000/dashboards

Step 4: Access the Grafana API anonymously to enumerate data sources and dashboards
curl -s http://<target-ip>:3000/api/dashboards/home
curl -s http://<target-ip>:3000/api/datasources


Steps to Reproduce:
1. Launch Kali Linux and perform a service scan against the target y-wing machine to identify the Grafana port: `nmap -sV -p 3000 <target-ip>`
2. Open a web browser and navigate directly to the Grafana interface using the identified port: `http://<target-ip>:3000`
3. Observe that the Grafana home dashboard loads fully without presenting any login prompt or requiring credentials
4. Navigate to the Dashboards section via the side menu: `http://<target-ip>:3000/dashboards` and confirm all dashboards are accessible
5. Click into any available dashboard and observe that real-time infrastructure metrics, host names, service states, and system data are displayed without restriction
6. Open a terminal and use `curl` to enumerate available data sources via the Grafana API: `curl -s http://<target-ip>:3000/api/datasources`
7. Enumerate all available dashboards via the API: `curl -s http://<target-ip>:3000/api/search?query=&`
8. Access individual dashboard JSON models to extract internal configuration and query details: `curl -s http://<target-ip>:3000/api/dashboards/uid/<dashboard-uid>`
9. Review the disclosed data and confirm that sensitive internal infrastructure information is exposed to an unauthenticated attacker
10. Verify the full extent of the exposure by confirming no session token, API key, or login is required at any point during the enumeration

Remediation:
1.    Immediately disable anonymous access    by setting `auth.anonymous.enabled = false` in the Grafana configuration file (`grafana.ini` or `defaults.ini`) and restart the Grafana service to apply the change
2. Implement mandatory authentication for all Grafana dashboard access and enforce strong password policies for all Grafana user accounts, removing any default credentials
3. Restrict network-level access to the Grafana port (default: 3000) using firewall rules so that only authorized internal IP ranges or VPN-connected hosts can reach the interface
4. Enable Grafana's role-based access control (RBAC) to ensure users are granted the minimum permissions necessary — Viewer, Editor, or Admin — based on their operational requirements
5. Configure Grafana to sit behind a reverse proxy (e.g., NGINX or Apache) with enforced TLS/HTTPS, ensuring credentials and session tokens are never transmitted in plaintext
6. Enable Grafana's built-in audit logging and integrate log output with a SIEM or centralized logging platform to detect and alert on unauthorized or anomalous access attempts
7. Periodically audit Grafana configuration files and user account permissions as part of a routine security review cycle to prevent misconfiguration drift

Discovered By:    Team 2

Date:    February 20, 2026
