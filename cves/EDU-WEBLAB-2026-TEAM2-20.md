CVE-ID: EDU-WEBLAB-2026-TEAM2-019

Title: XML External Entity (XXE) Injection in Configuration File Processing Enabling Unauthorized Data Exfiltration

Affected Lab: XML Configuration Validation Module

Component: Configuration XML parser

Severity: Critical

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

CVSS Score: 9.1

Description:
The XML Configuration Validation module is vulnerable to a critical XML External Entity (XXE) injection flaw. 
The vulnerability arises from the application’s use of an insecurely configured XML parser that processes Document Type Definitions (DTDs) and resolves external entities provided in user-supplied configuration files. 
An attacker can upload or submit a crafted XML configuration containing a SYSTEM entity targeting sensitive local files (e.g., /flag.txt, /etc/shadow, or application source code). During the validation phase, the parser resolves the entity's URI and replaces the entity reference with the actual content of the file. If the validation logic reflects the parsed values—such as echoing back the "validated" configuration or displaying error messages containing the resolved data—the content of the sensitive file is disclosed to the attacker. This vulnerability results in a direct breach of confidentiality and can be used as a stepping stone for SSRF or internal network mapping.

Proof of Concept:

XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE config [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<config>
  <server>
    <host>&xxe;</host>
    <port>8080</port>
  </server>
</config>

XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE config [
  <!ENTITY xxe SYSTEM "file:///proc/self/environ">
]>
<config>
  <server>
    <host>&xxe;</host>
    <port>8080</port>
  </server>
</config>

##Steps to Reproduce:

Navigate to the XML Configuration Validation module and locate the interface for uploading or pasting XML configuration data.
Submit a standard, valid XML configuration to establish a baseline of expected validation output (e.g., "Configuration for host HWASA is valid").
Insert Malicious DTD: Modify the XML configuration by adding a <!DOCTYPE> block before the root <config> element.
Define the External Entity: Inside the DTD, declare a SYSTEM entity (e.g., &xxe;) referencing a sensitive file on the server, such as file:///flag.txt.
Inject the Entity Reference: Place the &xxe; reference into an element that is likely to be reflected in the validation summary, such as the <host> tag.
Submit the crafted XML for validation.
Observe Validation Output: Review the response from the server. Confirm if the contents of the targeted file appear where the entity reference was placed.
Test for Parameter Entities: Attempt to use an XML Parameter Entity (% xxe;) to bypass basic filters that only look for general entities if the initial attempt is blocked.
Verify Network Access (SSRF): Point the SYSTEM entity to an internal IP or localhost port to determine if the parser can reach internal network segments.
Document the successfully exfiltrated data and any information disclosed about the underlying server filesystem to confirm the Critical severity.

##Remediation:

Disable External Entity Resolution: Configure the XML parser to explicitly ignore or disallow external entities. In Java (JAXP), set dbf.setFeature("http://xml.org/sax/features/external-general-entities", false); and dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);.
Disallow DOCTYPE Declarations Entirely: The most robust defense is to disable DTD processing completely. For most parsers, this is achieved by setting the feature http://apache.org/xml/features/disallow-doctype-decl to true.
Use Secure-by-Default Libraries: Update XML processing libraries to the latest versions. Modern frameworks like Jackson 2.x or updated SAX/DOM parsers often have these protections enabled by default.
Implement XSD Validation: Validate all uploaded configuration files against a strict XML Schema Definition (XSD) that does not allow DTDs or unexpected elements. Ensure validation occurs in a secure, non-resolving environment.
Whitelist Permitted Values: Instead of parsing the entire XML structure, use a logic that only extracts specific, whitelisted elements and validates their format (e.g., regex for IP addresses or hostnames).
Apply Least Privilege: Ensure the application process does not have read access to sensitive system files. Use a chroot jail or containerization to limit the parser's view of the filesystem.
Filter Outgoing Requests: Implement egress firewall rules to prevent the application server from initiating connections to external or internal IP addresses via the XML parser.
Enhanced Monitoring: Log all instances of XML parsing errors and configure alerts for any input containing the strings ENTITY, SYSTEM, or PUBLIC, which are indicative of XXE attempts.

Discovered By: Team 2

Date: March 20, 2026
