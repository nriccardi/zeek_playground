# conn.log
### Triage
* Port Scanning (many short connections S0 or REJ from same IP to different destination ports):
    1. Filter by conn_state == "S0" or conn_state == "REJ".
    2. Group by id.orig_h (origin IP).
    3. Check the frequency of connections to different destination ports (id.resp_p).
    4. Look for an unusually high number of connections to different ports within a short time window (e.g., 1 minute).
* DoS (high volume of traffic to the same destination IP with failed connections):
    1. Filter by conn_state == "REJ", conn_state == "RST", or failed status codes.
    2. Group by id.resp_h (destination IP).
    3. Calculate the total number of failed connections over a time period (e.g., 5 minutes).
    4. Look for multiple failed connections to the same IP (id.resp_h) from multiple source IPs (id.orig_h).
* C2 Communication (repeated connections to unusual destination IPs/ports, with constant duration or data size):
    1. Filter by duration > X (long duration, e.g., > 60 seconds) and consistent data sizes (orig_bytes and resp_bytes).
    2. Group by id.resp_h (destination IP) and id.resp_p (destination port).
    3. Check if the connections are consistently long and maintain steady data transfers.
    4. Investigate whether the destination IP/port pair is unusual or external to your network.
* Data Exfiltration (large transfer of bytes from internal source IP):
    1. Filter by orig_bytes > X (large amount of data, e.g., > 1MB).
    2. Group by id.orig_h (source IP).
    3. Check if the source IP is internal to your organization.
    4. Look for significant data transfer to external destination IPs (id.resp_h).

### Cols of interest

#### id.orig_h (Origin IP)
What to look for:
* High frequency of connections: Multiple connections from the same source IP in a short time frame could indicate suspicious activity like port scanning or DoS.
* Unusual IPs: External or unrecognized IP addresses trying to connect to internal servers or ports.

Why: The origin IP helps identify the source of the traffic. Unusual or frequent connections could be a sign of attacks.

#### id.orig_p (Origin Port)
What to look for:
* Common or known ports: Make sure the source port is legitimate (e.g., 80, 443 for HTTP/HTTPS). Unusual or ephemeral ports could indicate malware.

Why: Uncommon or ephemeral source ports may be indicative of malicious tools or attackers trying to mask their identity.

#### id.resp_h (Destination IP)
What to look for:
* Frequent connections to unfamiliar IPs: Repeated traffic to unusual destination IPs, especially external ones, could signal command-and-control (C2) or data exfiltration.
* Internal destination IP: Traffic to internal IPs that is not part of normal operations (e.g., large data transfer or unusual ports).

Why: Destination IP tells where the traffic is going. Repeated, suspicious connections could indicate a breach or scanning attempt.

#### id.resp_p (Destination Port)
What to look for:
* Unusual ports: Connections to ports that are not usually open on the server could indicate an attack, such as port scanning or exploiting unpatched vulnerabilities.
* Uncommon port scans: Repeated connections to non-standard ports from the same IP.

Why: Abnormal ports may indicate attacks or malicious activities, such as exploitation of unprotected services.

#### conn_state (Connection State)
What to look for:
* S0 (no reply) or REJ (rejected): A high number of S0 or REJ states could indicate a port scan or DoS attack.
* Frequent resets: Repeated RST states could signal a failed or disruptive connection attempt, often associated with scanning or attack patterns.

Why: Connection states provide insight into whether connections are being successfully completed. Anomalies in state can indicate scanning, denial of service, or other malicious activity.

#### proto (Protocol)
What to look for:
* Uncommon protocols: Ensure the protocols being used are appropriate for the type of network (e.g., TCP, UDP, ICMP). An unusual protocol (e.g., a non-standard port with UDP) could indicate malware or other suspicious activity.

Why: Some protocols are used for specific attacks (e.g., ICMP for DDoS attacks or UDP for DNS amplification attacks). Detecting unusual ones can signal malicious activity.

#### duration (Connection Duration)
What to look for:
* Too short: Extremely short connections (e.g., S0 state) could indicate probing or scanning attempts, where an attacker is quickly checking multiple ports.
* Too long: Excessive connection durations could indicate persistence, such as in C2 communication or exfiltration.

Why: The duration of connections helps identify abnormal patterns like C2 or exfiltration, or failed scans and DoS attacks.

#### orig_bytes (Origin Bytes)
What to look for:
* High byte count: A large number of bytes sent from the origin could indicate data exfiltration or the transfer of large files (such as malware).

Why: Large data transfers, especially from internal to external sources, may indicate an attempted data breach or exfiltration.

#### resp_bytes (Response Bytes)
What to look for:
* High byte count: Excessive response bytes from external destinations could indicate a large download or command response from a C2 server.

Why: Monitoring the response bytes can help identify data exfiltration or large downloads, often related to malware communication.


# dns.log

### Triage:
* DNS Tunneling (long/unusual domain names, unexpected query types):
    1. Filter for long domain names in query (e.g., more than 30 characters).
    2. Check if the qtype_name is TXT (commonly used for data tunneling).
    3. Look for patterns in the answers (e.g., TXT records containing base64 or random data).

* DGA Activity (random domain generation algorithms):
    1. Look for domains with high entropy (e.g., randomly generated domain names).
    2. Check rcode_name == "NXDOMAIN" which can indicate failed DGA attempts or connections.
    3. Compare the queried domains with a list of known DGAs or look for newly generated domains.

* DNS Exfiltration (repeated queries to suspicious domains):
    1. Filter by a high volume of queries to the same domain (e.g., multiple queries per minute).
    2. Investigate if the domain is external or suspicious (using threat intelligence feeds or domain reputation).
    3. Look for consistent querying patterns (same source IP id.orig_h querying a specific domain).

* Queries to Known Bad Domains:
    1. Cross-check the query field against a list of known malicious domains or threat intelligence feeds.
    2. Investigate any matches for further suspicious activity.

### Cols of interest
#### id.orig_h (Origin IP)
What to look for:
* Suspicious IPs: Repeated DNS queries from the same origin IP to unusual or unknown domains could suggest scanning or malicious behavior.

Why: Repeated DNS queries from a single IP could indicate attempts to gather information about the network or exfiltrate data.

#### id.resp_h (Response IP)
What to look for:
* Suspicious DNS servers: DNS responses from IPs that don't match expected DNS server addresses could indicate an attack, such as DNS poisoning or spoofing.

Why: Tracking where DNS queries are resolved (i.e., what servers are responding) can reveal if an attacker is redirecting traffic or using malicious DNS servers.

#### query (Domain Name)
What to look for:
* Long/unusual domain names: Very long domain names may indicate DNS tunneling (e.g., base64 encoded data).
* Frequent queries: A high frequency of queries to the same domain can suggest DNS exfiltration or botnet activity.

Why: Unusual or long domain names could be signs of tunneling or other malicious activity, while repeated queries to the same domain might indicate data exfiltration.

#### qtype_name (Query Type)
What to look for:
* Unexpected query types: Look for TXT records or other unusual types (e.g., MX, CNAME) being queried. These can be used in DNS tunneling or DGA (Domain Generation Algorithms).
* Unexpected types for a given query: For example, querying for an A record when you're expecting a TXT record can be indicative of misuse.

Why: Certain query types (like TXT) can be used for DNS tunneling or data exfiltration, while others might indicate DGA-related behavior.

#### answers (DNS Response)
What to look for:
* Unusual answers: Responses containing random or very suspicious data may indicate tunneling (e.g., base64 encoded text).
* Large response size: Large responses, especially if unusual, might indicate data exfiltration or malware communication.

Why: The answers show the actual data returned. Random or malicious content here could signal an attack or exfiltration.

#### rcode_name (Response Code)
What to look for:
* NXDOMAIN: Multiple NXDOMAIN responses could indicate DGA (Domain Generation Algorithm) or attempts to contact unreachable domains.
* Frequent failures: A large number of failed DNS queries could indicate that a DDoS attack is happening, or it could be due to scanning or misconfigurations.

Why: DNS response codes help identify the outcome of a DNS query. Failures or errors might suggest issues like DGA, tunneling, or misconfigured systems.

# http.log

**Triage:**

* Data Exfiltration (excessive POST requests, large response bodies, internal destination IP):
    1. Filter by method == "POST", id.orig_h (internal source), and orig_bytes > X.
    2. Look for repeated POST requests from the same internal IP to external destinations.
    3. For large response bodies, check resp_mime_type for unusual or executable content (e.g., .exe, .zip).

* SQL Injection (unusual URIs with suspicious characters):
    1. Look for uri with characters like ', ", --, ;, = that could indicate SQLi attempts.
    2. Check if the method is GET or POST, as SQL injection commonly targets these methods.
    3. Investigate the URI for query parameters that may be vulnerable to SQL injection.


* Unusual User-Agent (bot traffic):
    1. Check user_agent for known patterns associated with bots or automated tools (e.g., "curl", "wget").
    2. Look for patterns in host and uri accessed by suspicious user agents.

* Phishing (fake login pages in URI):
    1. Look for URIs that include keywords like login, signin, account, or any variations of login pages.
    2. Check if the host domain matches a legitimate service or is suspicious.

* Cross-Site Scripting (XSS):
    1. Check for `<script>` tags in uri or query parameters in the uri field.
    2. Look for common XSS payloads in the user_agent or referrer (e.g., "`><script>alert(1)</script>`).

* Brute Force (multiple failed login attempts):
    1. Look for repeated HTTP requests with method == "POST" to login endpoints (e.g., /login).
    2. Check for multiple 401 or 403 status codes indicating failed login attempts.

* Malware Download (suspicious file extensions or large downloads):
    1. Filter for uri containing suspicious file extensions (.exe, .zip, .bat).
    2. Check if the resp_mime_type matches a file type that could be malicious.
    3. Investigate any large downloads (orig_bytes > 1MB) from external sources.

### id.orig_h (Origin IP)
What to look for:
* High frequency of requests: A large number of requests from the same origin IP could indicate an attack, such as a brute force or DDoS attempt.
* Internal IPs accessing external resources: Unusual traffic patterns or suspicious behavior originating from internal IPs.

Why: The origin IP identifies where the traffic is coming from, and high volumes of requests or suspicious activity can help identify attacks.

### id.orig_p (Origin Port)
What to look for:
* Unusual ports: If requests are originating from unusual ports, this could be an indication of tools or malware trying to hide their activity.

Why: Certain ports could be indicative of automated tools or scripts using non-standard ports to avoid detection.

### id.resp_h (Destination IP)
What to look for:
* Internal IP destinations: Requests targeting internal servers, especially if there are unauthorized attempts to access sensitive resources.
* Frequent access to suspicious domains: A high frequency of traffic going to suspicious or unfamiliar destinations.

Why: The destination IP tells you where the traffic is being sent. Frequent or unauthorized access to internal servers or external malicious destinations could indicate malicious activity.

### id.resp_p (Destination Port)
What to look for:
* Uncommon ports: High traffic to uncommon ports may suggest a vulnerability is being targeted or exploited.

Why: Unusual ports may indicate a targeted attack or exploitation of a service running on non-standard ports.

### method (HTTP Method)
What to look for:
* Excessive POST requests: A high volume of POST requests, especially to login pages, could indicate brute force or data exfiltration.
* Unusual methods: Requests using DELETE, PUT, or CONNECT could indicate attempts to manipulate server resources.

Why: Different HTTP methods indicate the kind of interaction with the server. Suspicious methods or excessive use of certain methods can be red flags.

### uri (URI Path)
What to look for:
* Unusual or suspicious URIs: Look for paths like /login, /admin, or others that are typically targeted in brute force or phishing attacks.
* SQL injection patterns: Look for suspicious characters like


### resp_status_code (Response Status Code)
What to look for:
* 404 errors: A high number of 404 errors could indicate a scanning attempt for vulnerabilities (e.g., attackers probing for non-existent resources).
* 500 or 403 errors: These errors may indicate attacks like SQL injection attempts, denial of service, or unauthorized access attempts.

Why: HTTP status codes provide insight into how a server responds to requests. Patterns in these responses can help identify abnormal activity such as failed exploits, scanning, or brute force attempts.

### request_body_len (Request Body Length)
What to Look For:
* Unusually large request body: If the size of the request body is abnormally large, it may indicate an attempt to send a large payload, such as in a SQL injection, file upload, or data exfiltration attempt.
Sudden spikes in request body length: If the body length suddenly increases, this could indicate an attacker trying to exploit a vulnerability by sending large amounts of data.
* POST requests with large bodies: Since the POST method is often used for submitting forms, an unusually large request body might indicate a malicious payload, such as a web shell or large data that could be maliciously manipulated.

Why: The request body length (request_body_len) indicates how much data is being sent in the request. Large or suspicious payloads can often point to attacks like SQL injection, where attackers are trying to inject malicious code, or attempts to upload files, which can be part of a web shell attack or exfiltration attempt.

### response_body_len (Response Body Length)
What to Look For:
* Unusually large response body: A response body that is unexpectedly large could indicate malicious activity, such as an attacker downloading a large file (e.g., malware or exfiltrated data) or receiving a large amount of data after exploiting a vulnerability.
* Constantly large response bodies: If certain requests (e.g., command-and-control traffic) consistently result in large response bodies, this could indicate data exfiltration, a malicious file download, or C2 communication.

Why: The response body length (response_body_len) tells you how much data is being sent back to the client. A large response, especially if it comes from an unusual source or internal resource, can indicate the delivery of malware, large downloads, or attempts to retrieve large files from the target.

### user_agent (User Agent)
What to look for:
* Unusual or generic user agents: Look for user agents that seem generic or unusual, which may indicate bot traffic (e.g., curl, wget, or unknown agents).
* Anomalies in user agent strings: A sudden influx of a single user agent could indicate automated scraping, botnets, or brute force attempts.

Why: The user agent often provides clues about automated bots or scripts, which are common in many types of attacks (e.g., scraping, brute force).

### referrer (Referring URL)
What to look for:
* Suspicious or unknown referrers: Referrers that don't make sense in the context of your site or system (e.g., referrers from external, untrusted domains).
* Repeated traffic from certain referrers: A high volume of traffic from specific referrers might indicate an attack, like phishing or redirection schemes.

Why: The referrer field can help track if malicious or phishing sites are trying to redirect traffic to your site or if users are being manipulated via malicious links.

### resp_mime_type (Response MIME Type)
What to look for:
* Suspicious file types: Look for MIME types like application/x-msdownload, application/octet-stream, application/zip, etc., which may indicate file downloads, potentially malicious files, or malware.
* Mismatch between file types and expected response: If a page returns a file type that is not normally expected (e.g., an HTML page that returns application/pdf), it could indicate an attempt to exploit a vulnerability or serve malicious content.

Why: MIME types tell you what type of content is being delivered. Suspicious MIME types may indicate malware delivery or exploits.