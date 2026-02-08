Vulnerability Report

CVE-ID: EDU-WEBLAB-2026-TEAM2-002

Title:  Unauthenticated User Enumeration via Exposed API Endpoint

Affected Lab:  y-wing

Component:  API Endpoint - /api/org/users

Severity:  Medium

CVSS Vector:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

CVSS Score:  5.3

Description:
A user enumeration vulnerability was identified in the /api/org/users endpoint of the y-wing machine due to missing authentication and authorization controls. The endpoint exposes organizational user information to unauthenticated requests, allowing attackers to retrieve usernames, email addresses, and potentially other user metadata without any credentials. This information disclosure facilitates targeted attacks such as phishing campaigns, credential stuffing, and social engineering by providing attackers with a comprehensive list of valid system users. While the vulnerability does not directly compromise user accounts, it significantly reduces the attack surface complexity for subsequent exploitation attempts.

Proof of Concept:
bash
# Direct API call to enumerate users without authentication:
curl -X GET http://[y-wing-ip]/api/org/users

 Alternative using browser or tools like Burp Suite:
GET /api/org/users HTTP/1.1
Host: [y-wing-ip]


Steps to Reproduce:
1. Identify the target application running on the y-wing machine and note its IP address or hostname
2. Using a web browser, attempt to access the endpoint directly by navigating to `http://[y-wing-ip]/api/org/users`

3. Observe that the endpoint returns a response containing user information without requiring authentication credentials
4. Alternatively, use curl from Kali Linux terminal: `curl -X GET http://[y-wing-ip]/api/org/users`
5. Examine the JSON or XML response and identify the exposed user data fields such as usernames, email addresses, user IDs, roles, or other metadata
6. Verify that no authentication token, session cookie, or API key is required to access this sensitive information
7. Attempt to access the endpoint from different IP addresses or browsers to confirm that the vulnerability is not session-dependent
8. Document all user information disclosed, including the total number of users enumerated and the sensitivity of the exposed data fields
9. Confirm that this information could be leveraged for targeted attacks such as password spraying, phishing campaigns, or social engineering against the identified users

Remediation:
1. Implement mandatory authentication checks on all API endpoints, especially those returning sensitive user information, requiring valid session tokens or API keys
2. Apply role-based access control (RBAC) to ensure only authorized users with appropriate privileges can access the /api/org/users endpoint
3. Remove or restrict the /api/org/users endpoint entirely if it is not necessary for application functionality, following the principle of least exposure
4. Implement rate limiting on API endpoints to prevent automated enumeration attempts and reduce the risk of mass data harvesting
5. Return generic error messages that do not reveal whether users exist or whether authentication failed due to invalid credentials versus insufficient permissions
6. Deploy API gateway security controls with authentication enforcement and request validation before routing to backend services
7. Implement comprehensive API logging and monitoring to detect unusual access patterns or enumeration attempts against user-related endpoints

Discovered By:  Team 2

Date:  February 8, 2026
