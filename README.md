# DPI Engine - Deep Packet Inspection System

This document explains **everything** about this project - from basic networking concepts to the complete code architecture.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet](#5-the-journey-of-a-packet)
6. [Deep Dive: Each Component](#6-deep-dive-each-component)
7. [How SNI Extraction Works](#7-how-sni-extraction-works)
8. [How Blocking Works](#8-how-blocking-works)
9. [Running the Application](#9-running-the-application)
10. [Understanding the Output](#10-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
72: │ │ ┌──────────────────────────────────────────────────────────┐ │ │
73: │ │ │ TCP Header (20 bytes)                                    │ │ │
74: │ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
75: │ │ │ │ Payload (Application Data)                           │ │ │ │
76: │ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
77: │ │ │ └──────────────────────────────────────────────────────┘ │ │ │
78: │ │ └──────────────────────────────────────────────────────────┘ │ │
79: │ └──────────────────────────────────────────────────────────────┘ │
80: └──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │ (Node.js)   │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### JavaScript Port Features
- **Asynchronous I/O**: Uses Node.js `fs/promises` and `Streams` for efficient PCAP handling.
- **Protocol Support**: Ethernet, IPv4, TCP, UDP.
- **DPI Support**: TLS (SNI), HTTP (Host), DNS (Query).
- **Rule Engine**: Block by IP, Application Name, or Domain.

---

## 4. File Structure

```
packet_analyzer/
├── src/                        # Source files (JavaScript)
│   ├── pcap_io.js             # PCAP file reading/writing (Async)
│   ├── packet_parser.js       # Network protocol parsing
│   ├── dpi_utils.js           # SNI/Host/DNS extraction
│   ├── types.js               # Common structures and constants
│   ├── rule_manager.js        # Blocking rules management
│   ├── connection_tracker.js  # Flow tracking and reporting
│   ├── dpi_engine.js          # Main orchestrator
│   ├── main.js                # ★ Packet Summary Tool ★
│   └── main_dpi.js            # ★ DPI Engine CLI ★
│
├── package.json               # Project dependencies and scripts
├── generate_test_pcap.py      # Python script to create test data
├── test_dpi.pcap              # Sample capture for testing
└── README.md                  # This file!
```

---

## 5. The Journey of a Packet

Let's trace a single packet through the system:

### Step 1: Read PCAP File (Async)

```javascript
const reader = new PcapReader();
await reader.open("capture.pcap");
```

**What happens:**
1. Open the file using `fs.promises.open`.
2. Read the 24-byte global header and verify magic numbers.

### Step 2: Read Each Packet

```javascript
let raw;
while ((raw = await reader.readNextPacket())) {
    // raw.data contains the packet bytes
    // raw.header contains timestamp and length
}
```

### Step 3: Parse Protocol Headers

```javascript
const parsed = PacketParser.parse(raw);
```

**What happens (in packet_parser.js):**
Extracts Ethernet, IP, and TCP/UDP fields into a structured object.

### Step 4: Inspect Payload (DPI)

```javascript
// For HTTPS traffic (port 443)
const sni = SNIExtractor.extract(payload);
if (sni) {
    const appType = sniToAppType(sni); // e.g., AppType.YOUTUBE
}
```

### Step 5: Apply Rules and Forward/Drop

```javascript
if (ruleManager.shouldBlock(ip, port, appType, sni)) {
    // DROP: Don't write to output
} else {
    // FORWARD: Write to output PCAP
    await writer.writePacket(raw.header, raw.data);
}
```

---

## 6. Deep Dive: Each Component

### `pcap_io.js`
Handles reading and writing PCAP files.
- **PcapReader**: Uses `fs.promises` for non-blocking reads.
- **PcapWriter**: Uses `fs.createWriteStream` for high-performance sequential writes.

### `packet_parser.js`
Decodes raw bytes into protocol fields.
- Uses `Buffer` methods like `readUInt16BE` to handle network byte order.

### `dpi_utils.js`
The "brain" of the DPI engine.
- **SNIExtractor**: Parses TLS handshake records.
- **HTTPHostExtractor**: Uses regex to find the `Host:` header in HTTP requests.
- **DNSExtractor**: Decodes DNS query labels.

---

## 7. How SNI Extraction Works

We extract the Server Name Indication from the **TLS Client Hello** packet.

1. **Verify TLS Record**: Check for `0x16` (Handshake).
2. **Verify Handshake Type**: Check for `0x01` (Client Hello).
3. **Skip Body**: Skip version, random, session ID, cipher suites, and compression.
4. **Parse Extensions**: Find extension type `0x0000` (SNI).
5. **Extract Hostname**: Read the hostname string from the extension data.

---

## 8. How Blocking Works

The `RuleManager` checks packets against several criteria:

1. **IP Blacklist**: Blocks all traffic from a specific source IP.
2. **App Blacklist**: Blocks identified applications (e.g., `YOUTUBE`).
3. **Domain Blacklist**: Blocks based on the extracted SNI or Host header (supports substring matching).

Once a connection is blocked, all subsequent packets in that flow (same 5-tuple) are automatically dropped.

---

## 9. Running the Application

### Installation
Ensure you have [Node.js](https://nodejs.org/) installed.

```bash
# Clone the repository
git clone <repo-url>
cd packet-analyzer

# No external dependencies required for the JS port!
```

### Basic Packet Analyzer
To view a summary of packets in a PCAP file:
```bash
node src/main.js test_dpi.pcap [max_packets]
```

### DPI Engine with Blocking
To run the DPI engine and block specific traffic:
```bash
# Block YouTube and Facebook
node src/main_dpi.js input.pcap output.pcap --block-app YouTube --block-app Facebook

# Block a specific IP
node src/main_dpi.js input.pcap output.pcap --block-ip 192.168.1.100

# Block a domain
node src/main_dpi.js input.pcap output.pcap --block-domain example.com
```

---

## 10. Understanding the Output

The DPI engine prints a summary after processing:
- **Total Packets**: Count of all packets processed.
- **App Classification**: Breakdown of detected applications (YouTube, Google, etc.).
- **Forwarded/Dropped**: Number of packets written to the output file vs. blocked.
- **Connection Report**: List of all unique connections and their identified apps.

---
*Created as a high-performance JavaScript port of the original C++ DPI Engine.*
