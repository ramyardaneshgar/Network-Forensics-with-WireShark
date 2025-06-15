# THM-WireShark
Network forensics using Wireshark, TCP stream reassembly, HTTP object extraction, display filtering, and traffic anomaly detection across OSI layers.
## Introduction

Wireshark is a Layer 2–7 passive network traffic analyzer used extensively for packet capture (PCAP) analysis in incident response, intrusion detection, network performance debugging, and digital forensics. In this lab, I used `Exercise.pcapng` to demonstrate applied traffic analysis, full packet dissection, and forensic object recovery in a controlled environment.

---

## 1. Environment Setup and File Structure

Upon launching the TryHackMe room, I accessed the provided VM via browser-based split-screen interface. Two PCAP files were present:

* `http1.pcapng` — used to follow screenshots and UI demonstration
* `Exercise.pcapng` — main dataset for deep packet inspection

I opened `Exercise.pcapng` in Wireshark using:

```bash
File → Open → Exercise.pcapng
```

Wireshark loaded the capture file and parsed 58,620 packets in total. This was verified in the status bar.

---

## 2. Wireshark GUI and Analyst Tooling

Wireshark provides a three-pane interface:

* **Packet List Pane** (top): Indexed packets with metadata (No., Time, Source, Destination, Protocol, Info).
* **Packet Details Pane** (middle): Hierarchical protocol dissection mapped to OSI layers.
* **Packet Bytes Pane** (bottom): Raw hexadecimal/ASCII content, dynamically highlights bytes of the selected field.

### Toolbar Functions:

* Shark icon initiates a live capture session on selected interfaces.
* Display filter bar accepts BPF-like queries (e.g., `http`, `ip.addr == 192.168.1.1 && tcp.port == 443`).
* `View > Coloring Rules`: used to identify traffic types (e.g., green for HTTP, blue for DNS) based on protocol and flags.

---

## 3. Protocol Dissection – Deep Packet Analysis

I focused on **packet 38**, which contained HTTP application-layer data.

### Dissection by OSI Layers:

#### **Layer 1 (Frame):**

* Frame metadata includes capture interface ID, arrival timestamp, frame length, and protocol chain.
* Useful for verifying capture integrity and source of acquisition.

#### **Layer 2 (Data Link / Ethernet II):**

* Source MAC: `00:0c:29:2d:8c:cf`
* Destination MAC: `00:50:56:e4:2a:eb`
* Type: IPv4 (0x0800)
* Used to detect MAC spoofing, ARP poisoning, or switch-level traffic redirection.

#### **Layer 3 (Network / IPv4):**

* Source IP: `192.168.1.101`
* Destination IP: `207.142.131.235`
* TTL: `47`
  TTL is decremented by one at each router hop. A value of 47 suggests the packet has passed through 17 routers (assuming a Linux-like default TTL of 64).

#### **Layer 4 (Transport / TCP):**

* Source Port: 1053
* Destination Port: 80 (HTTP)
* Seq/Ack Numbers, TCP Flags, Window Size
* Payload length: `424` bytes
  TCP sequence and acknowledgment numbers are critical for detecting packet injection, retransmissions, or session hijacking.

#### **Layer 7 (Application / HTTP):**

* Method: `GET / HTTP/1.1`
* Host: `www.slashdot.org`
* User-Agent: `Mozilla/4.0`
* Content-Type: `application/xml`
* eTag: `9a01a-4696-7e354b00`

**Answer Highlights:**

* Markup Language: XML (application/xml in HTTP header)
* Arrival Date: 05/13/2004
* TTL: 47
* TCP Payload Size: 424 bytes
* eTag: `9a01a-4696-7e354b00`

This analysis validates that Wireshark accurately reconstructs Layer 7 headers and payloads, making it an effective tool for HTTP session reconstruction and metadata extraction.

---

## 4. File Carving and Metadata Correlation

### 4.1 String Search – Application Data Extraction

Using `Edit > Find Packet`, I searched for `r4w` in the “Packet Details” context. This surfaced a packet containing the artist ID:

```plaintext
r4w8173
```

This demonstrates Wireshark's capability to search payloads for human-readable strings, useful in C2 detection or credential harvesting scenarios.

### 4.2 Packet Comments – Instructional Payloads

I navigated to packet 12 and used:

```bash
Right-click → Packet Comment
```

The embedded comment directed me to packet 39765 for JPEG extraction. Comments are persisted in PCAPNG metadata and are valuable for team-based forensic workflows or analyst annotations.

### 4.3 JPEG Carving from PCAP

Steps:

1. Navigated to packet 39765
2. Expanded protocol headers to locate JPEG stream segment
3. Right-clicked on `JPEG File Interchange Format` → `Export Packet Bytes`
4. Saved as `extracted_image.jpg`
5. Computed MD5 hash:

```bash
cd ~/Desktop
md5sum extracted_image.jpg
```

**Result:** `911cd574a42865a956ccde2d04495ebf`

This shows a real-world use case of Wireshark in malware analysis—recovering payloads from HTTP/SMB traffic and validating their integrity through hash comparison.

### 4.4 HTTP Object Export – TXT File Extraction

I used:

```bash
File → Export Objects → HTTP
```

Filtered for `.txt`, exported `note.txt`, then used:

```bash
cd ~/Desktop
cat note.txt
```

**Extracted name:** `PACKETMASTER`

This simulates payload recovery from intercepted HTTP file transfers—a common task in data loss prevention (DLP) and e-discovery.

### 4.5 Expert Info Diagnostics

Navigated to:

```bash
Analyze → Expert Information
```

Wireshark flagged `1636` warnings including TCP retransmissions, ACKed untransmitted data, and TCP segment out-of-order conditions—potential indicators of connection instability or session tampering.

---

## 5. Filtering and Stream Reconstruction

### 5.1 Display Filters

From packet 4:

```bash
Right-click “Hypertext Transfer Protocol” → Apply as Filter → Selected
```

Generated query:

```bash
http
```

Displayed packets reduced to 1089. Display filters allow narrowing PCAPs to specific protocols, IPs, ports, or byte patterns for surgical analysis.

### 5.2 TCP Stream Analysis

Navigated to packet 33790:

```bash
Right-click → Follow → TCP Stream
```

Wireshark reassembled the bidirectional conversation, displaying client-to-server (red) and server-to-client (blue) traffic.

Using `Ctrl+F`, I searched for:

```plaintext
artist
```

* Total artists: 3
* Second artist: `Blad3`

TCP stream analysis is essential for:

* Reconstructing application-level data (chat, login)
* Validating HTTP POSTs
* Identifying plaintext credentials
* Analyzing C2 payloads

---

## Lessons Learned

1. **Protocol Dissection Depth:**
   Wireshark provides layered inspection capabilities that mirror OSI stack behavior. Understanding field dependencies (e.g., IP header flags affecting TCP session handling) enables better detection of crafted packets or exploit payloads.

2. **File Carving Relevance:**
   Exporting objects such as JPEG and TXT from packet data is directly applicable in malware forensics, ransomware payload analysis, and insider threat investigations.

3. **Metadata as Evidence:**
   Comments, Expert Info warnings, and packet annotations provide forensic breadcrumbs. These elements are routinely used in legal chain-of-custody or incident postmortems.

4. **Stream Reconstruction Accuracy:**
   Following TCP/UDP streams provides a forensic narrative that raw packet analysis alone cannot. It simulates attacker conversations, credential exchanges, and file transfers.

5. **Filtering as a Triage Tool:**
   Filtering reduces analyst fatigue by focusing only on threat-relevant traffic. Mastery of Wireshark filters enables efficient triage during live incidents.

