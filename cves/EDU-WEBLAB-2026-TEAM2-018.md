**CVE-ID**: EDU-WEBLAB-2026-TEAM2-18

**Title**: XML External Entity (XXE) Injection in SOAP Request Body Enabling Sensitive File Disclosure

**Affected Lab**: SOAP Request Processing Module

**Component**: SOAP XML parser and request handler

**Severity**: Critical

**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

**CVSS Score**: 9.1

Description:
A critical XML External Entity (XXE) vulnerability was identified in the SOAP Request Processing module. The vulnerability exists because the underlying XML parser used to process SOAP envelopes is configured to resolve external entities defined within the DOCTYPE declaration. An attacker can supply a crafted SOAP request containing a malicious SYSTEM entity pointing to sensitive local files or internal network resources. When the server processes the SOAP body, the parser resolves the entity, effectively embedding the contents of the target file into the XML data structure. If the application logic subsequently reflects the parsed data back in the SOAP response, the file contents are disclosed to the attacker. This flaw allows for unauthorized access to sensitive server-side information (such as configuration files, environment variables, or flags) and can be further leveraged to conduct Server-Side Request Forgery (SSRF) against internal services.

Proof of Concept:

XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///root/flag.txt">
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
  <!ENTITY xxe SYSTEM "file:///">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetData>
      <value>&xxe;</value>
    </GetData>
  </soap:Body>
</soap:Envelope>

Steps to Reproduce:

Access the SOAP Request Processing interface and identify the endpoint for submitting SOAP actions (typically an ASMX, WCF, or generic API endpoint).
Intercept a valid SOAP request using a proxy tool to understand the expected XML structure and the SOAPAction headers.
Insert Malicious DTD: Modify the request by inserting a <!DOCTYPE> declaration immediately after the XML prolog and before the <soap:Envelope> tag.
Define External Entity: Create a SYSTEM entity (e.g., &xxe;) referencing a known sensitive file on the target system, such as file:///root/flag.txt.
Reference Entity in SOAP Body: Replace a legitimate data value within the <soap:Body> (e.g., the content of the <value> tag) with the entity reference &xxe;.
Submit the modified SOAP request to the server.
Analyze SOAP Response: Observe the returned SOAP envelope. Check the XML elements for the reflected contents of the targeted file.
Verify SSRF vulnerability: Attempt to point the SYSTEM entity to an internal web service (e.g., http://localhost:8080) and observe if the service's HTML/JSON response is embedded in the SOAP response.
Test for OOB (Out-of-Band) Exfiltration: If the response does not reflect the data, attempt to trigger an external HTTP request to an attacker-controlled listener to confirm the parser's ability to reach external network locations.
Document the extracted data nodes and the successful bypass of data boundary controls to confirm a total compromise of file confidentiality within the parser's scope.

**Remediation**:

Disable DTDs and External Entities: The most effective defense is to configure the XML parser to completely disable DTD (Document Type Definition) processing. For most SOAP frameworks (e.g., JAX-WS, .NET WCF), set ProhibitDtd to true or use a Resolver that returns null for external entities.
Use Secure SOAP Frameworks: Ensure that the SOAP library in use is updated to the latest version. Many modern frameworks (like Apache CXF or WCF 4.5+) have XXE protections enabled by default.
Implement Strict Input Validation: Validate incoming SOAP requests against a strict XML Schema (XSD). Reject any requests that contain unexpected DOCTYPE declarations or entity references.
Sanitize XML Payloads: Implement a pre-processing layer that scans the raw request body for the string <!ENTITY or SYSTEM and blocks the request before it reaches the XML parser.
Enforce Least Privilege: Run the web service account with the lowest possible filesystem permissions. The service should not have read access to sensitive directories like /root/, /etc/shadow, or /windows/system32/config/.
Disable Entity Expansion Limit: To prevent DoS attacks (Billion Laughs), limit the maximum number of entity expansions allowed by the parser.
Apply Egress Filtering: Restrict the application server's ability to make outbound network calls (HTTP/SMB/FTP). This prevents the parser from fetching external DTDs or exfiltrating data via SSRF.
Logging and Alerting: Log all XML parsing errors and configure security monitoring to flag any requests containing DTD metacharacters, as these are rarely required for standard SOAP communications.

Discovered By: Team 2

Date: March 18, 2026
