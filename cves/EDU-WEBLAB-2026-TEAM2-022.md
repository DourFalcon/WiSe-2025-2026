CVE-ID: EDU-WEBLAB-2026-TEAM2-022

Title: XML External Entity (XXE) Injection in Document Parsing Engine Enabling Arbitrary File Read

Affected Lab: XML Document Parsing Module

Component: Document XML parser

Severity: Critical

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

CVSS Score: 9.1

Description:
A critical XML External Entity (XXE) vulnerability was identified in the XML Document Parsing Engine. The vulnerability is caused by an insecurely configured XML parser that processes Document Type Definitions (DTDs) and resolves external entities without proper restriction. An unauthenticated attacker can submit a crafted XML document containing a SYSTEM entity that references sensitive local files or internal network resources. Upon parsing, the engine resolves the entity and embeds the contents of the targeted file—such as /etc/passwd—directly into the application’s internal data structure. Because the application subsequently renders the parsed content in the output, the sensitive server-side data is disclosed to the attacker. This flaw constitutes a complete breach of confidentiality for any file accessible to the web service process and could be further exploited to conduct internal port scanning or Server-Side Request Forgery (SSRF).

Proof of Concept:

XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE document [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>
  <title>Standard Test</title>
  <content>&xxe;</content>
</document>

XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE document [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080">
]>
<document>
  <title>Network Probe</title>
  <content>&xxe;</content>
</document>

Steps to Reproduce:

Access the XML Document Parsing module interface.
Verify normal functionality by submitting a standard XML payload: <document><title>test</title><content>hello</content></document>.
Inject Malicious DTD: Insert a <!DOCTYPE> block after the XML declaration, defining a SYSTEM entity (e.g., &xxe;) targeting a sensitive file path such as file:///etc/passwd.
Reference the Entity: Use the defined entity reference &xxe; within the <content> tags of the document.
Submit the document for parsing.
Observe Parsed Output: Confirm that the contents of the /etc/passwd file appear in the rendered result, establishing that external entity resolution is active.
Test for Out-of-Band (OOB) resolution: If the output is not directly reflected, attempt to trigger an external HTTP request to a controlled listener using a SYSTEM URI to confirm the parser's egress capabilities.
Verify Lack of Input Filtering: Attempt to use different URI schemes (e.g., php://filter or expect:// if available) to determine the extent of the parser's capabilities.
Confirm Unauthenticated Access: Repeat the exploit in an incognito window to ensure no session or authentication is required to trigger the vulnerability.
Document the successfully retrieved data to confirm a total compromise of confidentiality within the parser's scope.

Remediation:

Disable External Entity Resolution: Configure the XML parser/factory to explicitly disable the resolution of external general entities and parameter entities.
Disallow DOCTYPE Declarations: The most effective defense is to completely disable DTD processing in the XML parser configuration (e.g., in Java, set http://apache.org/xml/features/disallow-doctype-decl to true).
Use Secure XML Libraries: Utilize modern, secure XML libraries that have XXE protections enabled by default. Ensure all dependencies are patched to the latest versions.
Implement Strict Input Validation: Sanitize and validate all user-supplied XML input before it reaches the parser. Reject any input containing <!DOCTYPE or <!ENTITY keywords.
Restrict XML Features: Configure the parsing environment to use a safe subset of XML features, avoiding any advanced or untrusted DTD constructs.
Apply Principle of Least Privilege: Run the document parsing service with a low-privileged account that lacks read access to sensitive system files and directories.
Implement Egress Filtering: Configure network-level firewalls to prevent the application server from initiating outbound connections to the internet or internal network segments via the XML parser.
Log and Monitor Parser Activity: Enable detailed logging for XML parsing failures and configure real-time alerts for the presence of DTD metacharacters in incoming request bodies.

Discovered By: Team 2

Date: March 21, 2026
