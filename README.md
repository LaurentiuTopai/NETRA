# NETRA — eBPF-based EDR/NDR with an Integrated Go (Wails) UI

![NETRA Dashboard](Images/Image1.png)

## Overview

NETRA is an Endpoint Detection and Response (EDR) system with Network Detection and Response (NDR) capabilities. The system uses **eBPF** to collect events directly from the Linux kernel (process creation, file operations, network connections), a **correlation and decision module in user-space rewritten entirely in Go**, an **automated response** mechanism (process isolation/quarantine), and a **desktop GUI** built in Go using the **Wails** framework and **React**.

The project is developed as part of a bachelor's thesis, aiming to demonstrate a complete malicious-behavior detection architecture — from kernel-level data collection to automated response and real-time visualization for the user.

---

## Architecture (New Go-Userspace Version)

The system went through a major refactor (from a userspace C monolith to a modular Go-based architecture). The eBPF engine is now compiled with `bpf2go` and integrated directly into the Wails desktop application.

```text
┌───────────────────────────────────────────────────────────────────────┐
│                               KERNEL SPACE                            │
│                                                                       │
│   edr.bpf.c        filer.bpf.c     network.bpf.c      rootkit.bpf.c   │
│   (processes)      (files)         (network)         (rootkit/hooks) │
│         │                 │               │                  │       │
│         └────────┬────────┴───────┬───────┴─────────┬────────┘       │
│                   │  (BPF ring buffers / perf events)│                │
└───────────────────┼───────────────────────────────────┼──────────────┘
                     │                                   │
┌────────────────────┼───────────────────────────────────┼──────────────┐
│                    USER SPACE (Go + Wails UI)                        │
│                    │                                   │             │
│          pkg/agent (bpf2go / cilium/ebpf)                            │
│          Loading and attaching BPF programs                          │
│                    │                                   │             │
│          pkg/detector (Detection rules)                              │
│          - Ransomware (Mass file writes)                             │
│          - Spyware (Sensitive files + Exfiltration)                  │
│          - HardwareBlock (Camera/Microphone/Speaker protection)      │
│          - Rootkit (Suspicious files/modules, hooking, hiding)       │
│                    │                                   │             │
│          pkg/events (runtime.EventsEmit)                            │
│                    │                                   │             │
│              React Frontend (App.jsx)                                │
│              - Alert dashboard (real-time)                           │
│              - Rootkit Watch (suspicious files, real-time)           │
│              - Network Monitor (live packets, Wireshark-like)        │
│                Filters: IP / Port / Protocol (TCP / UDP / ICMP)      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Components and Features

### 1. Ransomware Detection
- Monitors mass file writes (`sys_enter_openat`) using `filer.bpf.c`.
- Correlates events within a strict time window.
- Quarantines the process (`SIGSTOP`) if the modified-files threshold is exceeded.

### 2. Spyware Detection
- Monitors access to files considered sensitive (e.g. `/etc/passwd`, `/root/`, SSH configs).
- Correlates sensitive file access with outbound network connections (`sys_enter_connect`, `sys_enter_sendto`) to external IP addresses (`network.bpf.c`).
- Stops the process before data exfiltration completes.

### 3. Hardware Protection (HardwareBlockDetector)
- Blocks and alerts in real time on unauthorized access attempts to peripherals:
  - **Webcam:** `/dev/video*`, `/dev/media*`
  - **Microphone:** `/dev/snd/pcm*c`
  - **Speaker:** `/dev/snd/pcm*p`

### 4. Rootkit Detection (RootkitDetector) — *new module*
- Monitors, via `rootkit.bpf.c`, typical rootkit behavior indicators at the file and process level: files/modules created or modified in sensitive locations (e.g. `/lib/modules/`, `/etc/ld.so.preload`, overwritten binaries in `/usr/bin`, `/usr/sbin`), loading of suspicious kernel modules, and attempts to hide processes/files.
- Correlates suspicious events through `pkg/detector`, generating dedicated `[ROOTKIT]` alerts, distinct from ransomware/spyware alerts.
- Results are streamed to the UI through a dedicated feed, displayed in real time in the **Rootkit Watch** panel (see below).

### 5. Graphical Interface (UI)
- Built with **Wails v2** (Go backend) and **React + TailwindCSS** (frontend).
- Runs as a native desktop application on Linux.
- The eBPF engine is started automatically in a background goroutine when the app launches, so events and alerts reach the user's dashboard instantly and reactively.

#### 5.1 Rootkit Watch — *new*
- Dedicated, real-time panel that lists files/locations flagged as possible rootkit artifacts (kernel modules, modified system files, overwritten binaries).
- Each entry shows the file path, the responsible process (if known), the type of modification, and the timestamp, updated live as `RootkitDetector` emits new events.

#### 5.2 Network Monitor — *new, Wireshark-like*
- Live view of all packets passing through the network interface, captured via `network.bpf.c` and displayed directly in the UI, without needing a separate capture tool (tcpdump/Wireshark).
- For each packet, the following are displayed: source/destination IP, source/destination port, protocol, and size.
- **Live filters**, applicable directly from the interface:
  - by **IP address** (source and/or destination)
  - by **port** (source and/or destination)
  - by **packet type / protocol**: `TCP`, `UDP`, `ICMP`
- The panel works as an integrated "mini-Wireshark," useful both for investigating spyware alerts (data exfiltration) and for general observation of system-generated traffic.

---

## Project Structure

```
NETRA/
├── kernel/                # eBPF source code (C)
│   ├── edr.bpf.c          
│   ├── filer.bpf.c        
│   ├── network.bpf.c      
│   └── rootkit.bpf.c      # Rootkit detection (suspicious files/modules) - new
├── NewVersion/            # EDR module (Go Userspace)
│   ├── pkg/
│   │   ├── agent/         # eBPF entrypoint, bpf2go-generated files
│   │   ├── detector/      # Detection business logic
│   │   │   └── rootkit.go # RootkitDetector - new
│   │   ├── events/        # Sends alerts to the Wails UI
│   │   ├── response/      # Process isolation, quarantine
│   │   └── store/         # Process state management
│   └── main.go            # Standalone entrypoint (optional)
├── UI/
│   └── netra-ui/          # Graphical interface (Wails)
│       ├── app.go         # Links the UI to the eBPF backend
│       ├── frontend/      # React + Tailwind
│       │   ├── App.jsx        
│       │   ├── RootkitWatch.jsx   # Real-time rootkit file panel - new
│       │   ├── NetworkMonitor.jsx # Wireshark-like packet viewer - new
│       │   └── index.css
│       └── go.mod         # Imports NewVersion directly
├── Tests/                 # Python scripts for malware simulation
├── OldVersion/            # Old, monolithic, C-only version
├── Images/                # Documentation media assets
└── DEVELOPMENT_HISTORY.md # Detailed architectural log
```

---

## Build and Run

### System Requirements
- Linux with eBPF support (kernel ≥ 5.8 recommended).
- `clang`, `llvm`, `libbpf-dev` for compiling BPF.
- `Go` ≥ 1.25.
- Wails v2: npm/Node.js, native libraries (e.g. `libgtk-3-dev`, `libwebkit2gtk-4.1-dev`).

### Running the Full Application (with UI)
To start the EDR engine directly inside the graphical interface:
```bash
cd UI/netra-ui
sudo wails dev
```
*(Note: `sudo` is required because attaching eBPF programs requires administrator privileges.)*

To run the test scripts and see how alerts appear in the interface:
```bash
sudo python3 Tests/spywareTest.py
```

### Architectural Details and Issue History
See the working document `DEVELOPMENT_HISTORY.md` for in-depth details on the difficulties encountered, the reasoning behind the C-to-Go refactor, pointer fixes, memory leaks, and the challenge of integrating signals between Wails and the EDR.

---

## Changelog — Recent Update

**Added:**
1. **Rootkit detection module** (`rootkit.bpf.c` + `RootkitDetector`) — detects suspicious kernel files/modules, modifications in critical system locations, and hiding attempts, with dedicated `[ROOTKIT]` alerting.
2. **Rootkit Watch (UI)** — new panel in the interface, with real-time visualization of files flagged as possible rootkit artifacts.
3. **Network Monitor (UI)** — live, Wireshark-like packet viewer displaying all traffic passing through the network interface, with **filters by IP, port, and protocol (TCP / UDP / ICMP)**.
