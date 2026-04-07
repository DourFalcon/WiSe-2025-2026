CVE-ID: EDU-WEBLAB-2026-TEAM2-018

Title: XML External Entity (XXE) Injection via SOAP Request Enabling Unauthorized Local File Disclosure

Affected Lab: SOAP Response Module

Component: SOAP XML parser and response handler

Severity: Critical

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

CVSS Score: 9.1

Description:
The SOAP Response module contains a critical XXE vulnerability within its XML parsing logic. The application fails to properly restrict Document Type Definition (DTD) processing when handling incoming SOAP requests. Specifically, the XML parser is configured to resolve external entities, allowing an attacker to define a custom SYSTEM entity within the request's DOCTYPE. When the parser encounters an entity reference (e.g., &xxe;) within the SOAP body, it fetches the resource specified in the URI—in this case, local system files. Because the application logic reflects the processed value back to the user in the SOAP response, sensitive information is exfiltrated directly. This vulnerability facilitates the unauthorized disclosure of server-side files, such as /etc/passwd or configuration files, and provides a foothold for further server-side attacks or internal network reconnaissance.

Proof of Concept:

XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetData>
      <value>&xxe;</value>
    </GetData>
  </soap:Body>
</soap:Envelope>

XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///non/existent/path/for/error/testing">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetData>
      <value>&xxe;</value>
    </GetData>
  </soap:Body>
</soap:Envelope>

Steps to Reproduce:

Navigate to the SOAP request submission interface and identify the endpoint for the GetData action.
Intercept the standard SOAP request using a proxy tool to verify the XML structure and the Content-Type: text/xml (or application/soap+xml) header.
Inject Malicious DTD: Insert a <!DOCTYPE> declaration before the root <soap:Envelope> element, defining an external entity named xxe that points to file:///etc/passwd.
Reference the Entity: Replace the value of the <value> tag within the <soap:Body> with the entity reference &xxe;.
Submit the modified request to the server.
Analyze the Response: Verify that the server's response contains the contents of the /etc/passwd file, confirming that the parser resolved the external entity and the application reflected its content.
Test for Out-of-Band (OOB) resolution: Point the SYSTEM entity to an external URL (e.g., a Burp Collaborator or unique pingback ID) and check if the server initiates a DNS or HTTP request to the external address.
Verify unauthenticated access: Attempt the exploit without any session cookies or Authorization headers to confirm the vulnerability is accessible to unauthenticated remote attackers.
Assess impact on Windows environments: If the target is Windows-based, adjust the payload to file:///C:/Windows/win.ini to verify local file read capability on that OS.
Document the successfully exfiltrated data to confirm the "Critical" severity rating and the potential for a full system data breach.

Remediation:

Disable External Entities and DTDs: Explicitly configure the XML parser to disable DTD processing and external entity resolution. In Java-based SOAP engines, this typically involves setting the FEATURE_SECURE_PROCESSING attribute or disabling DISALLOW_DOCTYPE_DECL.
Use Secure XML Libraries: Upgrade to modern SOAP/XML libraries that block external entities by default. Ensure the library versions are current and patched against known XXE bypass techniques.
Implement Strict Input Validation: Validate and sanitize all incoming SOAP XML payloads against an allowlist of expected characters. Reject any payload containing the <!DOCTYPE or <!ENTITY keywords at the WAF or application entry point.
Enforce Strict Parsing Rules: Configure the parser to ignore all DTD declarations entirely (setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)).
Apply Principle of Least Privilege: Ensure the service account running the SOAP handler has the most restrictive filesystem permissions possible, preventing access to sensitive directories like /root, /etc, or /boot.
Limit Entity Expansion: Configure the XML parser to enforce limits on entity expansion (e.g., using XML_PARSE_HUGE settings cautiously) to protect against DoS attacks related to XML parsing.
Disable File Protocol Support: If possible, configure the XML parser to only allow specific, safe protocols (like http for specific endpoints) and explicitly block the file://, gopher://, and php:// wrappers.
Implement Real-Time Alerting: Monitor application logs for failed XML parsing attempts or the presence of XXE-related strings in incoming requests to identify and respond to active exploitation attempts.

Discovered By: Team 2

Date: March 19, 2026
