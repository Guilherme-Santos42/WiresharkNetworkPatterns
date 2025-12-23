# WiresharkNetworkPatterns
Documentation focused on pattern discovery in Wireshark, useful for identifying malware, suspicious behavior, and other types of unusual activity.
First, I'll give a very basic overview of Wireshark, and later in this documentation I'll focus in detail on pattern discovery using Malware-Traffic-Analysis.net.

# Starts Here #

1. Fundamentals and Overview (Wireshark 101)
Wireshark is an essential tool for creating and analyzing PCAP (network packet capture) files.

Main Interface: Allows you to specify interfaces for live capture or load existing PCAP files.

Packet Display: Provides critical information such as packet number, time, origin, destination, protocol, length, and general information.

Visual Highlighting: Uses color codes to identify danger levels and different protocols, facilitating visual detection of anomalies.

2. Data Collection Methods
To analyze traffic, you must first know how to collect it:

Network Taps: Physical implants between cables to intercept traffic.

MAC Flooding: Technique to stress the switch until it sends packets to all ports, allowing eavesdropping.

ARP Poisoning: Redirects traffic from a host to your own monitoring machine.

3. Operations and Packet Filtering
Filtering is the heart of efficient analysis, especially in large captures.

Capture Filters: Defined before capture to save only specific parts of the traffic (e.g., tcp port 80).

Display Filters: Changeable during analysis to reduce visible packets (e.g., tcp.port == 80).

Logical Operators: Use and (&&), or (||), eq (==), ne (!=), gt (>), and lt (<) to create complex queries.

Advanced Filters: * contains: Searches for specific values ​​within fields (e.g., http.server contains "Apache").

matches: Allows the use of regular expressions.

upper/lower: Converts strings to uppercase/lowercase to avoid case-sensitivity errors.

4. OSI Layer and Protocol Analysis
Wireshark dissects packets following the OSI model (Layers 1 to 7).

ARP (Layer 2): Connects IPs to MAC addresses. Check the opcodes: 1 for request and 2 for response.

ICMP (Layer 3): Used for diagnostics (ping/traceroute). Type 8 indicates a request and 0 indicates a response. Anomalies in packet size (>64 bytes) may indicate tunneling.

TCP (Layer 4): Focused on the three-way handshake (SYN, SYN-ACK, ACK).

DNS (Layer 7): Resolves names to IPs. DNS traffic in TCP 53 or queries with very long/encoded names are signs of suspicious activity (e.g., data exfiltration).

HTTP/HTTPS: HTTP sends data in plain text (GET/POST). HTTPS uses TLS for encryption, requiring decryption keys (SSLKEYLOGFILE) to view the content.

5. Traffic Analysis and Attack Patterns

To identify threats, you should look for specific patterns:

Nmap Scans: * TCP Connect: Complete handshake, usually with window_size > 1024.

SYN Scan: Does not complete the handshake, usually with window_size <= 1024.

UDP Scan: Identified by ICMP Type 3 Code 3 errors (unreachable port).

Man-in-the-Middle (MITM) Attack: Detected by ARP conflicts (two MACs claiming the same IP) or when the attacker's MAC becomes the destination of all HTTP traffic.

Credential Hunting: Wireshark has a menu in Tools -> Credentials that automatically extracts clear text passwords from protocols such as FTP and HTTP.

Log4j Vulnerability: Search for text patterns such as jndi:ldap or Exploit.class in POST requests.

6. Statistics and Auxiliary Tools

Protocol Hierarchy: Shows the protocol distribution in the capture to identify statistical anomalies.

Endpoints & Conversations: Lists all IPs and unique communications, allowing you to map who is talking to whom.

Firewall ACL Rules: Wireshark can generate ready-made firewall rules (iptables, Cisco IOS, etc.) based on selected packets to quickly block threats.


