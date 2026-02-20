# NAT Slipstreaming Mutation/Variation Taxonomy

---

## Classification Structure

NAT Slipstreaming is a class of browser-based attacks that exploit Application Level Gateway (ALG) connection tracking mechanisms built into NAT devices and firewalls. By visiting a malicious website, a victim's browser is weaponized to emit network packets that fool the NAT into opening inbound port-forwarding rules ("pinholes") — allowing an external attacker to reach TCP/UDP services behind the victim's firewall that were previously unreachable from the Internet.

The attack is fundamentally a **multi-stage chain** in which each stage manipulates a different structural component of the network stack. A successful NAT Slipstreaming attack requires all stages to succeed: the attacker must discover the victim's internal address, control packet boundaries to isolate forged protocol messages, inject ALG-recognized signaling traffic, bypass browser port restrictions, and ultimately poison the NAT's connection tracking table. The taxonomy below is organized by the structural component being manipulated at each stage.

### Cross-Cutting Exploitation Primitives (Axis 2)

These primitives apply across multiple categories and explain *why* each mutation works:

| Primitive | Mechanism | Applies To |
|-----------|-----------|------------|
| **Protocol Confusion** | HTTP/WebRTC data is interpreted as ALG-recognized protocol traffic (SIP, H.323, IRC) by the NAT | §3, §5 |
| **Side-Channel Leakage** | Browser APIs or timing differences expose internal network topology | §1 |
| **Segmentation/Fragmentation Control** | Attacker manipulates TCP MSS or UDP MTU to force predictable packet splitting | §2 |
| **API Surface Abuse** | WebRTC, TURN, STUN APIs are used for purposes far beyond their intended scope | §1, §2, §4 |
| **Integer Manipulation** | Port number overflow/truncation bypasses browser allowlists | §4 |
| **Stateful Expectation Poisoning** | NAT creates forwarding expectations based on forged signaling messages | §5 |

### Foundational Mechanism: ALG Connection Tracking

All NAT Slipstreaming variants exploit a single architectural assumption: **ALGs in NAT devices perform deep packet inspection on application-layer protocol signaling (SIP, H.323, FTP, IRC) and automatically open forwarding rules when they detect multi-port session negotiation.** The ALG parses each TCP segment or UDP datagram *individually*, checking whether the data portion begins with a recognized protocol method keyword. If the keyword is found, the ALG extracts IP addresses and port numbers from the message body and creates a connection tracking expectation — a temporary firewall pinhole that forwards future inbound traffic on that port to the internal host.

This design was created to support legitimate multi-port protocols (VoIP calls, file transfers) that negotiate secondary data channels during initial signaling. The security assumption — that only genuine protocol clients will generate these signaling messages — is catastrophically violated when a browser can be made to emit TCP segments or UDP datagrams whose data payload begins with a valid protocol keyword.

---

## §1. Internal Address Extraction

The attacker must discover the victim's private IP address (e.g., 192.168.1.x, 10.0.0.x) before crafting ALG protocol messages that reference it. The internal IP is embedded in the forged SIP or H.323 signaling to tell the NAT which host the pinhole should forward traffic to.

### §1-1. WebRTC ICE Candidate Leakage

WebRTC's Interactive Connectivity Establishment (ICE) protocol discovers local network interfaces to establish peer-to-peer connections. Browsers expose these candidates through the `RTCPeerConnection` API, which historically revealed the full private IP address.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct ICE candidate extraction** | JavaScript creates an `RTCPeerConnection`, adds a data channel, and reads the `candidate` attribute from the `onicecandidate` event. The `host` candidate contains the private IP. | Requires HTTPS in modern Chrome (HTTP blocks WebRTC IP disclosure); Chrome/Firefox/Edge |
| **HTTPS-to-HTTP relay** | Attack page loads over HTTPS to extract the IP via WebRTC, stores it in a URL parameter, then redirects to HTTP (required for the remaining attack stages since TLS prevents packet inspection by the NAT). The IP survives the redirect in the query string. | Requires browser to not enforce HSTS on the attack domain |
| **mDNS obfuscation bypass** | Modern browsers replace private IPs with mDNS hostnames (e.g., `a1b2c3d4.local`) in ICE candidates to prevent leakage. However, this can be bypassed on networks where mDNS resolution is functional — the attacker resolves the `.local` hostname to the actual IP, or exploits browser/platform inconsistencies where mDNS is not enforced (e.g., certain Android versions, enterprise-managed Chrome policies). | mDNS not universally enforced; platform-dependent |

### §1-2. TCP Timing Side-Channel

When WebRTC is unavailable (Safari, older IE, or mDNS-protected environments), the attacker uses network timing to infer the internal IP.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Gateway subnet discovery** | Hidden `<img>` tags are loaded targeting common gateway IPs (192.168.0.1, 192.168.1.1, 10.0.0.1, etc.). The `onerror`/`onload` event timing distinguishes between reachable hosts (TCP RST in ~1ms) and unreachable hosts (connection timeout in seconds). A fast RST reveals the active subnet. | Common gateway addresses must be predictable; works on all browsers |
| **Host enumeration within subnet** | After identifying the active /24 subnet, a second round of hidden image requests scans all 254 host addresses. The fastest responder (lowest latency) is identified as the victim's own machine, since local-host responses are near-instant. | Requires the victim's machine to have a service that generates TCP RST or HTTP response on the probed port |
| **Cross-protocol timing** | Variation that uses `fetch()` or `XMLHttpRequest` instead of images, measuring CORS error timing or connection-refused timing to map reachable hosts with higher precision. | CORS errors still reveal timing metadata |

### §1-3. DNS Rebinding for Address Inference

In environments where both WebRTC and timing attacks are mitigated, the attacker may use DNS rebinding to map the internal network topology.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Short-TTL rebinding** | The attack domain initially resolves to the attacker's server, then after a short TTL expires, resolves to an internal IP (192.168.x.x). The browser sends the next request to the internal target, and the response (or lack thereof) reveals whether the host is active. | Requires DNS resolver to honor short TTLs; mitigated by DNS pinning in some browsers |
| **0.0.0.0 rebinding** | DNS resolves to `0.0.0.0`, which some OSes interpret as localhost, bypassing blocklists that only filter `127.0.0.1` and RFC 1918 ranges. | OS-dependent behavior; partially mitigated in modern browsers |

---

## §2. Packet Boundary Engineering

The core technical challenge: the attacker must position a forged ALG protocol message (SIP REGISTER, H.323 Setup, IRC DCC) at the **exact start of a TCP segment or UDP datagram**. ALGs in NAT devices parse each segment/datagram individually — if the protocol keyword doesn't begin at byte 0 of the data payload, the ALG ignores the packet. Since the browser wraps everything in HTTP or WebRTC framing, the attacker must manipulate packet boundaries to "push" the forged message into its own isolated segment.

### §2-1. TCP Maximum Segment Size (MSS) Manipulation

The attacker's server controls the MSS value announced during the TCP handshake, which dictates the maximum size of TCP data segments the victim's IP stack will emit.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **MSS-forced segmentation** | During the SYN-ACK, the attacker's server sets a custom MSS (e.g., via `ip route replace ... advmss <value>` on Linux). The victim's TCP stack then splits outgoing data at this boundary. The attacker calculates padding bytes to insert before the SIP/H.323 payload in the HTTP POST body, ensuring the forged protocol message lands at the start of a subsequent TCP segment. | Attacker controls the TCP server and can set arbitrary MSS; victim OS respects MSS option |
| **Multipart boundary compensation** | Browsers using `multipart/form-data` encoding add boundary strings (e.g., `------WebKitFormBoundary...`) whose length varies between browsers and sessions. Firefox, in particular, uses variable-length boundaries that require adaptive padding. The attacker's server monitors whether the SIP payload landed correctly (via the NAT's IP rewriting behavior) and instructs the browser to retry with adjusted padding. After ~10 retries, Firefox stabilizes its boundary length. | Browser-specific boundary behavior; requires retry loop |
| **Incremental padding adjustment** | The attack server runs a packet sniffer on its interface, capturing each incoming TCP segment to verify payload alignment. If the SIP keyword is offset from byte 0, the server signals the browser to add/remove padding bytes and resubmit the form. This creates a feedback loop that converges on the exact padding needed. | Requires server-side packet capture capability |

### §2-2. UDP/IP Fragmentation via MTU Overflow

For UDP-based attacks (using WebRTC TURN), the attacker forces IP-layer fragmentation rather than TCP segmentation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **TURN username field stuffing** | The WebRTC TURN authentication mechanism includes a `username` field with no size or character restrictions. The attacker fills this field with crafted padding data that, when combined with the SIP payload, exceeds the path MTU. The IP stack fragments the UDP datagram into two IP packets. The second fragment begins with the attacker-controlled SIP payload, complete with a forged UDP header pointing to port 5060. | NAT/firewall must reassemble fragments or inspect individual fragments; TURN server cooperation |
| **MTU probing** | Before the fragmentation attack, a large (6000-byte) HTTP POST beacon is sent to the attacker's server. The server analyzes incoming packets to calculate: path MTU, IP header size (including options), TCP/UDP header size, and the exact byte offset where attacker-controlled data begins within each packet. This information is used to calculate precise fragmentation offsets. | Requires server-side packet analysis |
| **Fragment offset alignment** | The padding is calculated so that the IP fragment offset of the second fragment places the forged protocol header at exactly the start of the reassembled datagram's data portion, or (for NATs that inspect fragments individually) at the start of the second fragment's payload. | NAT fragment handling behavior varies by implementation |

### §2-3. Content-Type and Encoding Manipulation

The choice of HTTP encoding affects how browsers frame the payload, which in turn affects segment boundaries.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **multipart/form-data boundary exploitation** | Hidden form fields generate POST bodies with predictable structure. The `<textarea>` field contains the SIP/H.323 payload, and hidden fields before it provide padding. Boundary strings from the browser act as delimiters whose length must be accounted for. | Form-based submission; no CORS restrictions on form posts |
| **application/x-www-form-urlencoded padding** | URL-encoding expands certain characters (e.g., `=` → `%3D`), providing fine-grained control over payload size in single-byte increments. This allows more precise padding than multipart encoding. | Browser must use this encoding for the form |
| **chunked transfer encoding interaction** | Some browsers or HTTP libraries use chunked transfer encoding for large POST bodies, introducing chunk-size headers that shift payload positions. The attacker must account for these additional framing bytes. | Browser/HTTP stack dependent |

---

## §3. ALG Protocol Forgery

Once a forged protocol message is isolated at the start of a TCP segment or UDP datagram, the NAT's ALG parses it as legitimate signaling traffic. Different ALG protocols offer different capabilities and constraints.

### §3-1. SIP (Session Initiation Protocol) Forgery

SIP is the primary target of NAT Slipstreaming v1. SIP ALGs are nearly universal in consumer and enterprise NAT devices because VoIP is a common use case.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SIP REGISTER injection** | A forged `REGISTER sip:<domain>;transport=TCP SIP/2.0` message is placed at the TCP segment boundary. The `Contact` header contains `sip:<user>@<victim_internal_IP>:<target_port>;transport=TCP`. The SIP ALG parses this as a VoIP endpoint registration and creates a pinhole forwarding inbound traffic on `<target_port>` to the victim's internal IP. | NAT has SIP ALG enabled (default on most routers); traffic reaches port 5060 |
| **SIP INVITE injection** | A forged `INVITE sip:<user>@<domain> SIP/2.0` message triggers the ALG's call-setup logic. The SDP body specifies media ports, causing the NAT to open pinholes for RTP/RTCP traffic on arbitrary ports. | Less commonly used than REGISTER; requires SDP parsing by ALG |
| **Via header manipulation** | The `Via` header in SIP messages specifies the return path. The SIP ALG creates pinholes based on the first Via value. By crafting the Via header to reference specific ports, the attacker can control which ports the NAT opens. | SIP ALG must inspect Via headers (Cisco, Juniper implementations) |
| **IP confirmation via NAT rewriting** | When the SIP ALG processes a valid message, it rewrites the internal IP in the Contact/Via headers to the NAT's public IP. The attacker detects this rewriting (the response packet contains the public IP instead of the private IP they sent), confirming that the ALG was successfully triggered. This serves as a success oracle for the attack. | NAT performs IP rewriting on SIP messages (standard behavior) |

### §3-2. H.323 Protocol Forgery

H.323 is the primary target of NAT Slipstreaming v2. Its critical advantage: **H.323 call forwarding allows specifying a different internal IP than the victim's own address**, enabling the attacker to reach any device on the internal network.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **H.323 Setup-UUIE call forwarding** | A forged H.323 Setup message with User-to-User Information Element (UUIE) containing a `callForwarded` facility reason is injected. The forwarding address specifies an arbitrary internal IP (e.g., a printer at 192.168.1.50), causing the NAT to create a pinhole to that device — not the victim's machine. | NAT has H.323 ALG enabled; browser reaches port 1720 |
| **H.225.0 fastStart exploitation** | The fastStart element in H.323 Setup messages contains pre-negotiated media channel parameters (codec, ports). The ALG opens pinholes for these media channels immediately upon parsing the Setup message, before any call is actually established. | H.323 ALG supports fastStart processing |
| **Any-IP internal targeting** | Unlike SIP (where the Contact address typically matches the sender's IP), H.323 call forwarding inherently redirects to a third-party address. The attacker specifies any IP on the victim's /24 subnet (or wider, if the network topology is known), enabling targeted attacks against specific devices: printers, cameras, NAS boxes, IoT controllers. | Attacker knows or can enumerate internal network topology (via §1) |

### §3-3. IRC DCC (Direct Client-to-Client) Forgery

The original ALG abuse vector from the 2010 NAT Pinning attack. IRC DCC commands signal peer-to-peer file transfers and chat sessions, requiring the NAT to open ports.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DCC CHAT command injection** | A hidden HTML form submits a POST request to the attacker's server on port 6667 (IRC). The POST body contains newlines followed by `PRIVMSG <nick> :\x01DCC CHAT <name> <ip_decimal> <port>\x01\n`. The IRC ALG only inspects line-by-line, ignoring HTTP headers, and treats the DCC command as a legitimate chat request. | NAT has IRC ALG enabled; browser can reach port 6667 (now restricted) |
| **DCC SEND/FILE variants** | Same mechanism as DCC CHAT but using the SEND or FILE subcommands, which may trigger different ALG code paths or bypass signature-based filters that only look for CHAT. | ALG implementation parses other DCC subcommands |

### §3-4. FTP PORT/EPRT Forgery

FTP's active mode requires the client to tell the server which port to connect back to. FTP ALGs open pinholes based on PORT or EPRT commands.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **FTP PORT command injection** | A forged `PORT <h1>,<h2>,<h3>,<h4>,<p1>,<p2>` command is positioned at a TCP segment boundary on a connection to port 21. The ALG parses the IP and port and creates a forwarding expectation. | NAT has FTP ALG enabled; browser can reach port 21 (restricted in modern browsers) |
| **FTP EPRT (Extended Port) injection** | `EPRT |1|<ip>|<port>|` provides the same functionality in a different format. Some ALGs only check for PORT but not EPRT, or vice versa. | ALG implementation differences |

### §3-5. Other ALG Protocol Vectors

Additional ALG protocols that could theoretically be targeted, though no public exploit chains exist:

| Subtype | Protocol | Port | Mechanism | Status |
|---------|----------|------|-----------|--------|
| **RTSP media negotiation** | RTSP | 554 | `SETUP rtsp://...` messages negotiate media transport ports; ALG opens RTP pinholes | Port now browser-restricted; theoretical |
| **PPTP GRE tunnel setup** | PPTP | 1723 | Control connection negotiates GRE tunnel parameters; ALG creates GRE forwarding | Port now browser-restricted; theoretical |
| **TFTP port tracking** | TFTP | 69 | TFTP doesn't embed IPs but ALG tracks source port for response forwarding | Port now browser-restricted; limited utility |
| **H.225 RAS gatekeeper** | H.323 RAS | 1719 | Registration/Admission/Status messages to gatekeeper; ALG opens call channels | Port now browser-restricted |

---

## §4. Browser Port Access Mechanisms

Browsers maintain a restricted port list to prevent connections to known-dangerous services. NAT Slipstreaming requires reaching specific ALG-monitored ports, necessitating bypass techniques.

### §4-1. Unrestricted Port Exploitation

The simplest approach: target ALG protocols on ports that browsers don't block.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SIP port 5060 (pre-patch)** | Before browser patches in late 2020, port 5060 (SIP) was not on any browser's restricted list. HTML forms could POST directly to `http://attacker.com:5060/`, and the traffic would traverse the NAT's SIP ALG. | Pre-Chrome 87.0.4280.141, pre-Firefox 85, pre-Safari 14.0.3 |
| **Non-standard ALG ports** | Some NAT devices configure ALGs on non-standard ports or perform protocol detection heuristically (looking for SIP keywords on any port). If the ALG inspects all traffic rather than only traffic on the canonical port, the browser's port restrictions are irrelevant. | Vendor-specific ALG configuration; rare but possible |

### §4-2. WebRTC STUN/TURN Port Bypass

WebRTC's STUN and TURN protocols establish connections outside the browser's normal HTTP/HTTPS port restriction logic.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **STUN TCP to restricted ports** | WebRTC TURN connections over TCP can be established to any destination port. Critically, the browser's restricted-ports list is **not consulted** for STUN/TURN connections. This allows the attacker to reach port 1720 (H.323), port 21 (FTP), port 6667 (IRC), and other restricted ports via WebRTC. | Browser supports WebRTC with TCP TURN; this was the primary v2 bypass before patches |
| **TURN UDP fragmentation delivery** | TURN over UDP allows the attacker to send large payloads that fragment at the IP layer. The fragmented packets bypass port-based filtering because only the first fragment contains the UDP header with the port number; subsequent fragments are identified only by fragment ID and offset. | NAT/firewall reassembles UDP fragments or passes them through |

### §4-3. Integer Overflow Port Wrapping

Port numbers in TCP/UDP are 16-bit values (0–65535). Browsers validate against restricted lists using wider integer types.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **65536 addition bypass** | When port 6667 (IRC) was restricted, the attacker specified port 72203 (6667 + 65536). The browser accepted this non-restricted value, but the TCP stack truncated it to 16 bits, producing the original port 6667 on the wire. | Older browser/OS combinations that didn't validate port range; largely patched |
| **Negative port interpretation** | Specifying negative port values that, when cast to unsigned 16-bit, produce the restricted port number. Similar to the addition bypass but exploiting signed/unsigned conversion. | Extremely implementation-specific; rare |

### §4-4. Non-HTTP Transport Channels

Using browser capabilities other than direct HTTP connections to deliver payloads.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WebSocket to ALG port** | WebSocket connections may bypass restricted port lists in some browser versions, allowing persistent TCP connections to ALG ports for ongoing protocol manipulation. | Browser-specific; mostly patched |
| **Beacon API / sendBeacon** | The `navigator.sendBeacon()` API sends POST requests with fewer restrictions. In some implementations, port checking may differ from fetch/XHR. | Implementation-specific |

---

## §5. Connection Tracking Poisoning

The ultimate goal: manipulate the NAT's connection tracking (conntrack) table to create forwarding expectations that allow inbound traffic from the attacker to the victim's internal services.

### §5-1. Expectation Creation via Signaling Parsing

When the ALG detects a valid signaling message, it creates a "related" connection expectation in the NAT's state table.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SIP Contact-based expectation** | The SIP ALG parses the `Contact: <sip:user@IP:PORT>` header and creates a DNAT expectation: future inbound TCP/UDP connections to PORT are forwarded to the internal IP. The NAT also rewrites the Contact header to use its public IP, confirming successful poisoning. | SIP ALG active; forged REGISTER reaches ALG |
| **H.323 media channel expectation** | The H.323 ALG parses fastStart or H.245 OpenLogicalChannel messages, extracting media transport addresses (IP:port pairs) and creating forwarding expectations for each negotiated media channel. | H.323 ALG active; forged Setup message reaches ALG |
| **Pinhole lifetime exploitation** | Connection tracking expectations have configurable timeouts (typically 30–300 seconds for SIP, longer for H.323). The attacker refreshes the expectation by periodically re-triggering the signaling message before the timeout expires, maintaining a persistent pinhole. | Attacker can sustain the browser session |

### §5-2. Source Port Manipulation

NATs may rewrite the source port of outgoing connections. The attacker must ensure the forged protocol traffic arrives at the ALG's expected port.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct port targeting** | If the NAT doesn't rewrite source ports for traffic to known ALG ports (e.g., outgoing traffic to port 5060 keeps its source port), the attack is straightforward. | NAT port preservation; common in consumer routers |
| **ALG forced port forwarding** | Even when the NAT rewrites source ports, the ALG's pinhole creation is based on the *signaling content* (the IP:PORT in the SIP Contact header), not the transport-layer source port. The ALG forces the NAT to create a forward for the specified port regardless of the connection's actual source port. | Standard ALG behavior |

### §5-3. Linux conntrack Helper Exploitation

On Linux-based NAT devices (including most consumer routers), connection tracking helpers are kernel modules that implement ALG logic.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **nf_conntrack_sip automatic activation** | In Linux kernels before 4.7, conntrack helpers were automatically activated for all traffic on their configured port. Any packet with SIP-like content arriving on port 5060 would be processed by the SIP helper — no validation of whether the connection was actually a SIP session. | Linux kernel < 4.7; or `nf_conntrack_helper=1` sysctl |
| **nf_conntrack_h323 expectation creation** | The H.323 conntrack helper creates expectations based on H.225/H.245 signaling. The helper trusts the IP addresses in call setup messages to create DNAT expectations, enabling the v2 any-IP targeting attack. | nf_conntrack_h323 module loaded |
| **nf_conntrack_ftp PORT tracking** | The FTP conntrack helper parses PORT commands and creates expectations for the specified data connection. This enables the FTP variant of the attack. | nf_conntrack_ftp module loaded |
| **Helper assignment bypass** | Even when automatic helper assignment is disabled (kernel ≥ 4.7), many distributions re-enable it for backward compatibility, or assign helpers via iptables CT target rules that match broadly (e.g., all traffic to port 5060). | Distribution/configuration dependent |

---

## §6. Target Scope Expansion

Different attack variants offer different scopes of access — from the victim's own machine to the entire internal network.

### §6-1. Single-Host Targeting (v1 Scope)

The original NAT Slipstreaming and NAT Pinning attacks open pinholes only to the victim's own IP address.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Victim-machine service exposure** | SIP REGISTER with the victim's own internal IP in the Contact header. The pinhole forwards a specified port to the victim machine. The attacker can then connect to any service running on that port: SSH, RDP, HTTP admin panels, database services. | Service must be listening on the target port on the victim machine |
| **Port scanning via sequential pinholes** | By repeating the attack with different port numbers, the attacker can sequentially open pinholes to scan the victim's machine for open services. Each attempt requires a full attack cycle (padding + SIP injection + ALG trigger). | Attack can be repeated within a single browser session |

### §6-2. Any-IP Network Targeting (v2 Scope)

The H.323 call-forwarding capability allows specifying an arbitrary internal IP, dramatically expanding attack scope.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Targeted device exploitation** | The attacker specifies the IP of a known internal device (discovered via §1 or guessed from common DHCP ranges) in the H.323 forwarding message. The NAT opens a pinhole to that device. Targets include: printers (IPP/SNMP), IP cameras (RTSP/HTTP), NAS devices (SMB/SSH), IoT controllers, SCADA/ICS systems. | H.323 ALG enables third-party IP forwarding; attacker knows target IP |
| **Network sweep** | The attacker iterates through the /24 (or wider) subnet, attempting H.323 call-forwarding to each address. Combined with port scanning, this maps the entire internal network topology and service landscape from an external position. | Requires many attack iterations; browser must remain on malicious page |
| **Pivot chaining** | After gaining access to an internal device via a pinhole, the attacker uses that device as a pivot point for deeper network penetration. For example: access a printer's web admin panel → exploit a known firmware vulnerability → establish a reverse shell → scan deeper network segments. | Internal device must have exploitable services |

### §6-3. Cross-Network Attacks

In certain architectural scenarios, the attack scope extends beyond a single NAT boundary.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Double-NAT traversal** | In networks with cascaded NATs (ISP-level CGNAT + customer NAT), the attack may trigger ALGs at both levels, though this significantly increases complexity and reduces reliability. | Both NAT devices must have ALG enabled for the same protocol |
| **Ad/iframe-based mass targeting** | The attack payload can be embedded in malicious advertisements or iframes on popular websites, enabling mass exploitation without targeted phishing. Every visitor to the ad-serving page becomes a potential victim whose NAT is probed. | Ad network doesn't filter JavaScript; victim's NAT has ALG enabled |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Impact |
|----------|-------------|---------------------------|--------|
| **Single-victim service exposure** | Any NAT with SIP ALG | §1-1 + §2-1 + §3-1 + §4-1 + §5-1 | Attacker reaches one port on victim's machine |
| **Full victim machine scan** | Any NAT with SIP ALG | §1 + §2-1 + §3-1 (repeated) + §5-1 | Attacker maps all services on victim |
| **Internal network device compromise** | NAT with H.323 ALG | §1 + §2 + §3-2 + §4-2 + §5-1 | Attacker reaches any device on LAN |
| **IoT/unmanaged device targeting** | NAT with H.323 ALG + IoT network | §1 + §3-2 + §6-2 | Attacker accesses cameras, printers, SCADA |
| **Mass exploitation via ads** | Any vulnerable NAT + ad network | §6-3 + all prior stages | Broad-scale internal network probing |
| **Lateral movement enablement** | Enterprise NAT + segmented network | §3-2 + §6-2 + §6-3 | External attacker gains network foothold |

---

## Historical Evolution

| Year | Milestone | Key Innovation | Scope |
|------|-----------|---------------|-------|
| **2010** | NAT Pinning (DEF CON 18 / Black Hat) | IRC DCC command injection via HTML form submission to port 6667 | Victim machine only; IRC ALG |
| **2020 Oct** | NAT Slipstreaming v1 | SIP ALG exploitation via TCP MSS manipulation + WebRTC IP extraction; bypasses browser port restrictions by targeting unrestricted port 5060 | Victim machine only; SIP ALG |
| **2020 Nov** | Browser port 5060 restricted | Chrome, Firefox, Safari add 5060/5061 to restricted ports | Partial mitigation |
| **2021 Jan** | NAT Slipstreaming v2 | H.323 ALG exploitation via WebRTC STUN (bypasses restricted port list); any-IP targeting via call forwarding | Any device on internal network; H.323 ALG |
| **2021 Feb** | Browser patches for v2 | Chrome 87.0.4280.141, Firefox 85, Safari 14.0.3; STUN restricted-port bypass fixed | Significant mitigation |
| **2021 Mar** | Chrome blocks 7 additional ports | Ports 69, 137, 161, 554, 1719, 1720, 1723, 6566 added to restricted list | Prophylactic mitigation |
| **2021 Apr** | Chrome blocks port 10080 | Port 10080 restricted (Firefox already blocked it) | Incremental mitigation |
| **2022+** | Private Network Access / Local Network Access | W3C spec requiring CORS preflight for requests from public to private networks; Chrome enforcement begins | Structural defense at browser level |

---

## CVE / Vulnerability Mapping

| Mutation Combination | CVE / Advisory | Affected Product | Impact |
|---------------------|---------------|-----------------|--------|
| §1-1 + §2-1 + §3-1 + §4-1 | CVE-2020-28041 | Netgear Nighthawk R7000 (NAT SIP ALG) | Remote access to any TCP/UDP service on victim machine |
| §4-2 (STUN port bypass) | CVE-2020-16043 | Chromium (< 87.0.4280.141) | Browser restricted port list bypass via WebRTC STUN |
| §4-2 (STUN port bypass) | CVE-2021-23961 | Firefox (< 85.0) | Browser restricted port list bypass via WebRTC |
| §4-2 (STUN port bypass) | CVE-2021-1799 | Safari / WebKit (< 14.0.3) | Browser restricted port list bypass |
| §1-1 (ICE candidate leak) | CVE-2021-21210 | Chrome | WebRTC IP address leak enabling internal IP discovery |
| §5-3 (conntrack helper) | — | Linux kernel nf_conntrack_sip | Automatic ALG activation without session validation (pre-4.7 default) |

---

## Detection Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **samyk/slipstream** | Offensive PoC | NAT Slipstreaming v1 + v2 full chain | Complete browser-based exploit; JavaScript + Python server |
| **jrozner/slipstream** | Offensive PoC | ALG abuse testing | Server/client implementation for testing ALG behavior |
| **samyk/natpinning** | Offensive PoC (legacy) | NAT Pinning via IRC DCC | Original 2010 exploit tool |
| **Sophos XG Firewall IPS** | Defensive IPS | NAT Slipstreaming detection | Signature-based detection of SIP/H.323 in HTTP POST traffic |
| **Palo Alto Threat Prevention** | Defensive IPS | NAT Slipstreaming v1/v2 | Threat prevention signatures blocking forged ALG traffic |
| **Fortinet FortiGuard IPS** | Defensive IPS | NAT Slipstreaming detection | IPS signature `NAT.SlipStreaming.Security.Bypass` |
| **Check Point IPS** | Defensive IPS | NAT Slipstreaming v1/v2 | IPS protections + ALG hardening guidance |
| **IPFire** | Defensive firewall | ALG disabling | Removed all ALGs by default after NAT Slipstreaming disclosure |
| **Browser DevTools / Wireshark** | Analysis | Packet boundary verification | Manual inspection of TCP segment alignment and ALG triggering |
| **conntrack-tools (Linux)** | Diagnostic | Connection tracking inspection | `conntrack -L` to monitor expectation table for unauthorized pinholes |

---

## Defensive Architecture

### Browser-Level Defenses

| Defense | Mechanism | Effectiveness |
|---------|-----------|---------------|
| **Restricted port list** | Browsers block HTTP/HTTPS/FTP to ALG-associated ports (5060, 5061, 1720, 6667, 21, 69, 554, etc.) | High for direct connections; bypassed by WebRTC STUN (pre-patch) |
| **WebRTC IP masking (mDNS)** | Private IPs in ICE candidates replaced with `.local` hostnames | Partial; depends on mDNS resolver availability |
| **Private Network Access (Local Network Access)** | CORS preflight required for requests from public origins to private/local networks; private targets must respond with `Access-Control-Allow-Private-Network: true` | Strong structural defense; enforcement rolling out gradually |
| **STUN restricted port enforcement** | WebRTC STUN/TURN connections now consult the restricted port list | Closes v2's primary bypass vector |

### Network-Level Defenses

| Defense | Mechanism | Effectiveness |
|---------|-----------|---------------|
| **Disable unused ALGs** | Remove SIP, H.323, FTP, IRC ALG modules from NAT/firewall configuration | Most effective; eliminates the root cause |
| **Conntrack helper hardening** | Set `nf_conntrack_helper=0` on Linux; assign helpers only via explicit CT target rules | Prevents automatic ALG activation on all traffic |
| **ALG packet validation** | Require full protocol compliance (not just keyword at segment start); validate that SIP traffic originates from a genuine SIP UA | Implementation-dependent; not widely available |
| **Egress filtering** | Block outgoing traffic to known ALG ports from non-VoIP hosts | Reduces attack surface; requires network segmentation |
| **IDS/IPS signatures** | Detect SIP/H.323 keywords embedded in HTTP POST bodies | Effective for known patterns; may be evaded by encoding variations |

---

## Summary: Core Principles

NAT Slipstreaming exploits a fundamental architectural tension in network security: **ALGs must inspect and modify application-layer protocol content to support multi-port protocols through NAT, but they lack the context to distinguish legitimate signaling from forged traffic embedded in browser-generated HTTP requests.** The root cause is not a bug in any single implementation — it is an inherent design flaw in the ALG concept itself. ALGs were designed in an era when protocol traffic came from dedicated applications, not from browsers executing arbitrary JavaScript. The assumption that "traffic on port 5060 is SIP" was reasonable when only SIP phones used that port; it is catastrophically wrong when browsers can be directed to submit HTTP POST data to any port.

Incremental patches have addressed individual attack vectors — browsers now block ALG ports, mask WebRTC IPs, and enforce restricted-port lists on STUN connections. But these are band-aids over the fundamental problem. As long as NAT devices contain ALGs that automatically create forwarding expectations based on packet content, new bypass vectors will emerge. The v1-to-v2 evolution demonstrates this: when SIP port 5060 was restricted, the attack pivoted to H.323 on port 1720 via STUN; when STUN was patched, the focus shifted to other delivery mechanisms.

The structural solution requires two parallel efforts: (1) **eliminating ALGs from NAT devices** — modern VoIP and multimedia protocols use ICE/STUN/TURN for NAT traversal and do not need ALGs, making them a legacy attack surface with minimal legitimate utility; and (2) **browser-enforced Private Network Access**, which shifts the security boundary from the network perimeter (which the browser can bypass) to the browser itself (which mediates all web-originated requests). The W3C Private Network Access specification, currently being implemented across major browsers, represents the most promising structural defense: it requires explicit opt-in from internal network targets before a public website can reach them, fundamentally inverting the ALG trust model.

---

## References

- Samy Kamkar, "NAT Slipstreaming" (2020) — https://samy.pl/slipstream/
- Samy Kamkar, Ben Seri & Gregory Vishnipolsky (Armis), "NAT Slipstreaming v2.0" (2021) — https://samy.pl/slipstream/ , https://www.armis.com/research/nat-slipstreaming-v2-0/
- Samy Kamkar, "NAT Pinning" (2010) — https://samy.pl/natpin/
- samyk/slipstream GitHub repository — https://github.com/samyk/slipstream
- jrozner/slipstream GitHub repository — https://github.com/jrozner/slipstream
- WICG, "Private Network Access" specification — https://wicg.github.io/private-network-access/
- WICG, "Local Network Access" specification — https://wicg.github.io/local-network-access/
- IETF, "Using Multicast DNS to protect privacy when exposing ICE candidates" — https://www.ietf.org/archive/id/draft-ietf-mmusic-mdns-ice-candidates-02.html
- RFC 8900, "IP Fragmentation Considered Fragile" — https://datatracker.ietf.org/doc/html/rfc8900
- regit/secure-conntrack-helpers, "Secure use of iptables and connection tracking helpers" — https://github.com/regit/secure-conntrack-helpers
- IPFire, "Security Announcement: Mitigating NAT Slipstreaming" — https://www.ipfire.org/blog/security-announcement-mitigating-nat-slipstreaming
- Sophos, "NAT Slipstreaming Advisory" — https://www.sophos.com/en-us/security-advisories/sophos-sa-20201207-nat-slipstreaming
- Palo Alto Networks, "PAN-SA-2021-0002" — https://security.paloaltonetworks.com/PAN-SA-2021-0002
- Chromium, "Port 5060 blocking" — https://bugzilla.mozilla.org/show_bug.cgi?id=1674735

---

*This document was created for defensive security research and vulnerability understanding purposes.*
