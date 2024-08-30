# Cooked-Cracker

## Overview

Cooked-Cracker is a Go-based tool designed to replace Linux cooked headers in packet capture (PCAP) files with fake Ethernet headers. This tool is particularly useful for processing PCAP files captured on Linux systems that use the "any" interface or in situations where the original link-layer headers are not preserved.

## What it Does

The main functionality of Cooked-Cracker includes:

1. Reading input PCAP files containing packets with Linux cooked headers.
2. Replacing these headers with predefined Ethernet headers.
3. Writing the modified packets to a new output PCAP file.

## What's Special About Cooked-Cracker

Cooked-Cracker stands out from other packet manipulation tools in several ways:

1. **Specialized Focus**: Unlike general-purpose packet manipulation tools, Cooked-Cracker is specifically designed to handle the conversion of Linux cooked headers to Ethernet headers. This focused approach ensures high efficiency and accuracy in this particular task.

2. **Preservation of Original Data**: While replacing the headers, Cooked-Cracker maintains the integrity of the original packet data. This ensures that the actual network traffic information remains unchanged and analyzable.

3. **Flexible Header Handling**: The tool is capable of detecting different versions of SLL headers (including SLL2) and adjusting its behavior accordingly, providing better compatibility with various capture scenarios.

4. **Minimal Dependencies**: With its reliance on only the `gopacket` library, Cooked-Cracker is easy to build and deploy across different environments.

These features make Cooked-Cracker an invaluable tool for network administrators, security researchers, and anyone working with packet captures from Linux systems, especially when dealing with captures from the "any" interface or other scenarios that produce Linux cooked headers.

## Installation
### Clone the repository:
```
git clone <repository-url>
cd cooked-cracker
```

### Install dependencies:

```
go mod tidy
```

### Build the project:

```
go build
```


## Usage

```
./cooked-cracker <input.pcap> <output.pcap>
```

- `<input.pcap>`: The path to the input PCAP file containing packets with Linux cooked headers.
- `<output.pcap>`: The path where the modified PCAP file with Ethernet headers will be saved.

## Requirements

- Go 1.18 (where x is the version used in your project)
- github.com/google/gopacket library


## Background

### What is a Linux Cooked Header?

A Linux cooked header, also known as SLL (Linux cooked-mode capture) or LINUX_SLL, is a special packet header format used by Linux when capturing packets on the "any" interface or when the original link-layer headers are not available.

The Linux cooked header typically includes:
- Packet type
- ARPHRD_ type
- Link-layer address length
- Source MAC address (if applicable)
- Protocol type

### Why Replace the Cooked Header?

There are several reasons to replace the Linux cooked header with an Ethernet header:

1. **Compatibility**: Some network analysis tools may not properly recognize or handle Linux cooked headers, leading to parsing errors or incomplete analysis.

2. **Standardization**: Ethernet headers are more widely supported and understood, making the PCAP files more portable across different analysis platforms.

3. **Reconstruction**: In some cases, you might want to reconstruct the original Ethernet frame structure for more accurate analysis or replay of network traffic.

4. **Tool Requirements**: Certain networking tools or simulators might specifically require Ethernet headers to function correctly.

### Why Does Linux Use Cooked Headers?

Linux uses cooked headers when capturing packets in situations where the original link-layer headers are not available or when capturing on virtual interfaces. This commonly occurs when:

1. Capturing on the "any" interface, which aggregates traffic from all interfaces.
2. Capturing on certain types of virtual interfaces (e.g., some VPN tunnels).
3. The kernel is configured to strip link-layer headers for performance reasons.

By using cooked headers, Linux can provide a consistent format for captured packets across various interface types, while still preserving essential information about the original packet.


## License

This project is licensed under the MIT License.


## Contributing

Feel free to contribute to this project. This is being actively maintained by Avneesh Hota.
