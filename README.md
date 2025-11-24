# TTL Whisper

**Covert channel communication through ICMP TTL manipulation**

TTLwhisper encodes secret messages into ICMP echo request packets by mapping morse 
code symbols to specific TTL value ranges. Unlike payload-based steganography, this 
technique hides data in packet headers, making it difficult to detect through 
standard deep packet inspection.

## How It Works

1. **Encode**: Converts plaintext message to morse code with letter separators
2. **Map**: Assigns TTL ranges to morse symbols (dots, dashes, separators)
3. **Randomize**: Selects random TTL within each range to avoid patterns
4. **Transmit**: Sends ICMP packets with encoded TTL values
5. **Decode**: Receiver captures packets and reverse-engineers message from TTL sequence

## Features

- Cross-platform support (Windows/Linux/macOS)
- Randomized TTL values within ranges for stealth
- Optional jitter packets to evade pattern detection
- Configurable packet timing and delays
- Companion decoder script for PCAP analysis
- Educational tool for network forensics and CTF challenges

## Use Cases

- Network forensics training and CTF competitions
- Red team covert channel demonstrations
- Security research and IDS/IPS testing
- Understanding ICMP-based exfiltration techniques

## Technical Description

TTLwhisper implements a covert channel using ICMP echo requests with steganographically 
encoded TTL (Time-To-Live) values. The tool converts plaintext to morse code, then maps 
each morse symbol to a specific TTL range:

  • Dot (.)        : TTL 32-64
  • Dash (-)       : TTL 65-96  
  • Letter Sep (|) : TTL 97-128
  • Word Sep (/)   : TTL 129-160
  • Jitter (noise) : TTL 161-192

By randomizing the exact TTL within each range, the tool creates variable packet 
signatures that resist simple pattern matching. The technique is protocol-compliant 
and generates minimal anomalies in network traffic analysis tools.

Detection requires statistical analysis of TTL distributions across multiple packets 
or baseline comparison with normal ICMP behavior for the host OS.
