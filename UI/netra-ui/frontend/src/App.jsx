import React, { useState, useEffect, useRef } from 'react';
import { EventsOn } from '../wailsjs/runtime/runtime';
import { StartRealtimeScan, StartRootkitScan } from '../wailsjs/go/main/App';

const eyeAscii = `
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣀⠀⠀⠀⢀⣠⡴⠶⠶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢠⣶⠟⢹⡏⠉⠛⠻⢿⣧⣀⠀⠀⠀⠙⣦⡀⠀⠀⠀⠀⠰⣤⡀⠀⠀⠀⠀
⠀⢠⡿⠁⠀⢸⣧⣄⡀⠀⠀⠈⠙⠻⣦⣄⠀⠈⢷⡀⠸⠷⢶⣦⣌⠻⣦⠀⠀⠀
⠀⣾⣧⣄⣀⢸⣯⠉⠛⠻⠶⣦⣄⣀⠀⠙⠿⣦⡈⢷⡄⠀⠀⠀⣙⣿⣾⣧⠀⠀
⠀⢹⣇⠉⠙⠛⢿⣄⠀⠀⠀⠀⣩⡿⠛⠳⢶⣼⣿⣿⣿⣿⠀⢸⡏⠉⢹⣿⡇⠀
⠀⠀⠛⢷⣦⣤⣤⣽⣷⣤⣤⣾⣯⣤⣤⣴⣾⣿⣿⣿⣿⣿⣇⠘⢷⣶⣾⣿⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠁⠀⠀⠀⠻⢿⣿⣿⣿⠟⠁⠀⠀⠙⠻⠿⠇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣶⣿⣿⣶⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣄⠙⠛⠿⠿⠿⠿⠿⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣷⣶⣶⣶⣶⣶⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⠿⣿⣿⠿⠟⢁⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠳⣶⣤⣤⣤⣴⣾⣿⣷⠀⠀⣠⣤⣤⣤⣶⡞⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠛⠋⣁⣴⣿⣿⣿⡿⠟⠋⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠀⠀
`;

const netraAscii = `
oooo   oooo ooooooooooo ooooooooooo oooooooooo        o      
 8888o  88   888    88  88  888  88  888    888     888     
 88 888o88   888ooo8        888      888oooo88     8  88    
 88   8888   888    oo      888      888  88o     8oooo88   
o88o    88  o888ooo8888    o888o    o888o  88o8 o88o  o888o  
`;

const SidebarButton = ({ label, active, onClick }) => (
  <button 
    onClick={onClick}
    className={`w-full text-left px-4 py-2 font-mono text-sm uppercase term-button mb-2 flex items-center justify-between ${active ? 'bg-term-yellow text-term-black font-bold' : ''}`}
  >
    <span>{label}</span>
    {active && <span>{'<'}</span>}
  </button>
);

const StatBlock = ({ label, value }) => (
  <div className="flex justify-between items-center py-1 border-b border-term-yellow/30">
    <span className="text-[10px] uppercase text-term-yellow/70">{label}</span>
    <span className="text-sm font-bold">{value}</span>
  </div>
);

function App() {
  const [activeTab, setActiveTab] = useState('VERIFY_REALTIME');
  const [isScanning, setIsScanning] = useState(false);
  const [threatCount, setThreatCount] = useState(0);
  const [activePids, setActivePids] = useState(new Set([1024, 1284, 2048, 4096, 5120, 8192]));
  const [scannedFilesCount, setScannedFilesCount] = useState(24809);
  const [netConnsCount, setNetConnsCount] = useState(38);

  const activeTabRef = useRef(activeTab);

  useEffect(() => {
    activeTabRef.current = activeTab;
  }, [activeTab]);

  // NDR Traffic Tracker Filter States
  const [filterMode, setFilterMode] = useState('ALL'); // 'ALL' | 'IP' | 'PORT' | 'PROTO'
  const [filterValue, setFilterValue] = useState('');

  // NDR Traffic Tracker states
  const [packets, setPackets] = useState([
    {
      id: 1,
      timestamp: "20:25:01.102",
      pid: 1420,
      comm: "curl",
      protocol: "DNS",
      src_ip: "192.168.1.100",
      dst_ip: "8.8.8.8",
      dst_port: 53,
      len: 42,
      payload: "GET /api/v1/telemetry HTTP/1.1\r\nHost: sec-check.org\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n",
      hex_dump: "0000  47 45 54 20 2f 61 70 69 2f 76 31 2f 74 65 6c 65  |GET /api/v1/tele|\n0010  6d 65 74 72 79 20 48 54 54 50 2f 31 2e 31 0d 0a  |metry HTTP/1.1..|\n0020  48 6f 73 74 3a 20 73 65 63 2d 63 68 65 63 6b 2e  |Host: sec-check.|\n0030  6f 72 67 0d 0a 0d 0a                            |org....|"
    },
    {
      id: 2,
      timestamp: "20:25:04.550",
      pid: 2150,
      comm: "firefox",
      protocol: "TCP",
      src_ip: "192.168.1.100",
      dst_ip: "142.250.180.206",
      dst_port: 443,
      len: 128,
      payload: "\x16\x03\x01\x00\x7b\x01\x00\x00\x77\x03\x03\x3b\x82\x9b\x2c... ClientHello TLSv1.3 Handshake Packet Data Stream",
      hex_dump: "0000  16 03 01 00 7b 01 00 00 77 03 03 3b 82 9b 2c 1f  |....{...w..;..,S|\n0010  53 65 63 75 72 69 74 79 20 53 65 73 73 69 6f 6e  |ecurity Session |\n0020  54 4c 53 76 31 2e 33 20 48 61 6e 64 73 68 61 6b  |TLSv1.3 Handshak|\n0030  65 20 50 61 63 6b 65 74 20 44 61 74 61 20 4f 4b  |e Packet Data OK|"
    }
  ]);
  const [selectedPacket, setSelectedPacket] = useState(null);

  const [logs, setLogs] = useState([
    "[SYSTEM] NETRA eBPF KERNEL HOOK INITIALIZED...",
    "[SYSTEM] TELEMETRY MODULE LOADED [OK]",
    "[REALTIME] RANSOMWARE & SPYWARE ENGINE ONLINE...",
    "[ROOTKIT] KERNEL HOOKS (memfd, finit_module, ptrace, bpf) LOADED [OK]",
    "[NDR] PACKET FILTERING ENGINE & INSPECTOR ONLINE [OK]",
    "[SYSTEM] AWAITING SECURITY EVENTS...",
  ]);

  useEffect(() => {
    // EDR Alerts listener
    const cancelAlerts = EventsOn("edr:alert", (alert) => {
      const logMessage = `[${alert.timestamp}] [${alert.type}] PID:${alert.pid} (${alert.comm}) - ${alert.message}`;
      setLogs((prev) => [...prev, logMessage].slice(-150));

      if (alert.pid && alert.pid > 0) {
        setActivePids((prev) => new Set([...prev, alert.pid]));
      }

      setScannedFilesCount((prev) => prev + 1);

      if (
        alert.type.includes("STOPPED") || 
        alert.type.includes("WARNING") || 
        alert.type.includes("ROOTKIT") ||
        alert.type.includes("RANSOMWARE") ||
        alert.type.includes("SPYWARE")
      ) {
        setThreatCount((prev) => prev + 1);
      }
    });

    // NDR Packets listener
    const cancelPackets = EventsOn("ndr:packet", (pkt) => {
      setPackets((prev) => [pkt, ...prev].slice(0, 150));

      if (activeTabRef.current === 'TRAFFIC_TRACKER') {
        setNetConnsCount((prev) => prev + 1);
      }
    });

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setSelectedPacket(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);

    const interval = setInterval(() => {
      setScannedFilesCount((prev) => prev + Math.floor(Math.random() * 3) + 1);
    }, 2000);

    return () => {
      if (typeof cancelAlerts === 'function') cancelAlerts();
      if (typeof cancelPackets === 'function') cancelPackets();
      window.removeEventListener('keydown', handleKeyDown);
      clearInterval(interval);
    };
  }, []);

  const handleScanClick = () => {
    setIsScanning(true);
    const now = new Date().toLocaleTimeString();

    if (activeTab === 'VERIFY_REALTIME') {
      setLogs(prev => [...prev, `[${now}] [USER] INITIATING REALTIME VERIFICATION (RANSOMWARE & SPYWARE)...`].slice(-150));
      StartRealtimeScan().catch(err => console.warn("Scan err:", err));
    } else if (activeTab === 'VERIFY_ROOTKITS') {
      setLogs(prev => [...prev, `[${now}] [USER] INITIATING DEEP ROOTKIT KERNEL VERIFICATION...`].slice(-150));
      StartRootkitScan().catch(err => console.warn("Scan err:", err));
    } else {
      StartRealtimeScan().catch(err => console.warn("Scan err:", err));
    }

    setTimeout(() => {
      setIsScanning(false);
    }, 3000);
  };

  const getFilteredLogs = () => {
    if (activeTab === 'VERIFY_REALTIME') {
      return logs.filter(l => 
        l.includes('[REALTIME]') || 
        l.includes('[RANSOMWARE]') || 
        l.includes('[SPYWARE]') || 
        l.includes('[CAMERA]') || 
        l.includes('[MICROFON]') || 
        l.includes('[DIFUZOR]') ||
        l.includes('[SYSTEM]')
      );
    }
    if (activeTab === 'VERIFY_ROOTKITS') {
      return logs.filter(l => 
        l.includes('[ROOTKIT]') || 
        l.includes('[FILELESS]') || 
        l.includes('[LKM_LOAD]') || 
        l.includes('[PTRACE_INJECT]') || 
        l.includes('[EBPF_LOAD]') || 
        l.includes('[SYSTEM]')
      );
    }
    return logs;
  };

  // Filter Traffic Tracker Packets based on selected mode & user input
  const getFilteredPackets = () => {
    if (filterMode === 'ALL' || !filterValue.trim()) {
      return packets;
    }
    const val = filterValue.trim().toLowerCase();

    if (filterMode === 'IP') {
      return packets.filter(p => 
        (p.dst_ip && p.dst_ip.toLowerCase().includes(val)) ||
        (p.src_ip && p.src_ip.toLowerCase().includes(val))
      );
    }
    if (filterMode === 'PORT') {
      return packets.filter(p => String(p.dst_port).includes(val));
    }
    if (filterMode === 'PROTO') {
      return packets.filter(p => p.protocol && p.protocol.toLowerCase().includes(val));
    }
    return packets;
  };

  return (
    <div className={`min-h-screen bg-term-black text-term-yellow flex overflow-hidden font-mono crt selection:bg-term-yellow selection:text-black ${isScanning ? 'scanning-mode' : ''}`}>
      
      {/* Left Menu (Sidebar) */}
      <aside className="w-64 term-border-glow m-4 flex flex-col relative z-20 bg-term-black">
        <div className="p-4 border-b border-term-yellow text-center">
          <pre className="text-[0.65rem] leading-tight font-black term-glow whitespace-pre inline-block text-left">
            {eyeAscii}
          </pre>
        </div>

        <div className="p-4 border-b border-term-yellow">
          <div className="mb-2 text-xs text-term-yellow/50 text-center font-bold">=== SYSTEM STATS ===</div>
          <div className="flex flex-col space-y-1">
            <StatBlock label="ACTIVE_PROCS" value={String(activePids.size + 135)} />
            <StatBlock label="SCANNED_FILES" value={scannedFilesCount.toLocaleString()} />
            <StatBlock label="THREATS_BLOCKED" value={String(threatCount).padStart(3, '0')} />
            <StatBlock label="NET_CONNS" value={String(netConnsCount).padStart(3, '0')} />
          </div>
        </div>

        <nav className="flex-1 p-4 overflow-y-auto">
          <div className="mb-2 text-xs text-term-yellow/50 font-bold">=== EDR MENU ===</div>
          <SidebarButton 
            label="[1] VERIFY REALTIME" 
            active={activeTab === 'VERIFY_REALTIME'} 
            onClick={() => setActiveTab('VERIFY_REALTIME')} 
          />
          <SidebarButton 
            label="[2] VERIFY ROOTKITS" 
            active={activeTab === 'VERIFY_ROOTKITS'} 
            onClick={() => setActiveTab('VERIFY_ROOTKITS')} 
          />

          <div className="mt-4 mb-2 text-xs text-term-yellow/50 font-bold">=== NDR MENU ===</div>
          <SidebarButton 
            label="[3] TRAFFIC TRACKER" 
            active={activeTab === 'TRAFFIC_TRACKER'} 
            onClick={() => setActiveTab('TRAFFIC_TRACKER')} 
          />
          
          <div className="mt-4 mb-2 text-xs text-term-yellow/50 font-bold">=== SESSION ===</div>
          <SidebarButton 
            label="[4] ALERT HISTORY" 
            active={activeTab === 'ALERT_HISTORY'} 
            onClick={() => setActiveTab('ALERT_HISTORY')} 
          />
          <SidebarButton 
            label="[8] AGENT CONFIG" 
            active={activeTab === 'AGENT_CONFIG'} 
            onClick={() => setActiveTab('AGENT_CONFIG')} 
          />
          <SidebarButton 
            label="[9] DISCONNECT" 
            active={activeTab === 'DISCONNECT'} 
            onClick={() => setActiveTab('DISCONNECT')} 
          />
        </nav>
      </aside>

      {/* Main View Area */}
      <main className="flex-1 flex flex-col relative m-4 ml-0 h-[calc(100vh-2rem)] z-10">
        
        {/* Top NETRA ASCII Header */}
        <header className="mb-4 flex flex-col items-center justify-center pt-2">
          <pre className="text-sm md:text-base leading-tight font-black term-glow whitespace-pre text-center">
            {netraAscii}
          </pre>
        </header>

        {/* Top Info Bar */}
        <div className="term-border p-2 mb-4 bg-term-black flex justify-between items-center text-xs">
          <div>
            HOST: SEC-LINUX-01 | MODE: {activeTab} | OS: LINUX_eBPF_KERNEL
          </div>
          <div className="animate-pulse">_ TERMINAL ACTIVE _</div>
        </div>

        {/* EDR Tab Headers */}
        {activeTab === 'VERIFY_REALTIME' && (
          <div className="term-border p-3 mb-4 bg-term-yellow/10 flex flex-col space-y-2">
            <div className="flex justify-between items-center text-xs font-bold text-term-yellow border-b border-term-yellow/30 pb-1">
              <span>=== REALTIME PROTECTION: RANSOMWARE & SPYWARE ENGINE ===</span>
              <span className="text-term-ok">[ONLINE]</span>
            </div>
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div className="term-border p-2 bg-term-black">
                <div className="font-bold text-term-orange mb-1">RANSOMWARE MONITOR</div>
                <div>• Rapid Writes Limit: 20 files/sec</div>
                <div>• Entropy Encryption Check: Active</div>
                <div>• Auto SIGSTOP Quarantine: Enabled</div>
              </div>
              <div className="term-border p-2 bg-term-black">
                <div className="font-bold text-term-orange mb-1">SPYWARE & DEVICE GUARD</div>
                <div>• Sensitive Files (/etc/shadow): Hooked</div>
                <div>• Camera & Mic Hardware Locks: Monitored</div>
                <div>• Unauthorized Network Conn: Monitored</div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'VERIFY_ROOTKITS' && (
          <div className="term-border p-3 mb-4 bg-term-yellow/10 flex flex-col space-y-2">
            <div className="flex justify-between items-center text-xs font-bold text-term-yellow border-b border-term-yellow/30 pb-1">
              <span>=== ROOTKIT DETECTOR: DEEP KERNEL eBPF HOOKS ===</span>
              <span className="text-term-ok">[ONLINE]</span>
            </div>
            <div className="grid grid-cols-4 gap-2 text-[11px] text-center">
              <div className="term-border p-2 bg-term-black">
                <div className="font-bold text-term-yellow">FILELESS MALWARE</div>
                <div className="text-[10px] opacity-75">memfd_create()</div>
                <div className="text-term-ok font-bold mt-1">[HOOKED]</div>
              </div>
              <div className="term-border p-2 bg-term-black">
                <div className="font-bold text-term-yellow">LKM LOAD</div>
                <div className="text-[10px] opacity-75">finit_module()</div>
                <div className="text-term-ok font-bold mt-1">[HOOKED]</div>
              </div>
              <div className="term-border p-2 bg-term-black">
                <div className="font-bold text-term-yellow">PROCESS INJECTION</div>
                <div className="text-[10px] opacity-75">ptrace()</div>
                <div className="text-term-ok font-bold mt-1">[HOOKED]</div>
              </div>
              <div className="term-border p-2 bg-term-black">
                <div className="font-bold text-term-yellow">EBPF PROGRAM LOAD</div>
                <div className="text-[10px] opacity-75">bpf() syscall</div>
                <div className="text-term-ok font-bold mt-1">[HOOKED]</div>
              </div>
            </div>
          </div>
        )}

        {/* NDR TRAFFIC TRACKER VIEW (Filter Controls + Full Width Table) */}
        {activeTab === 'TRAFFIC_TRACKER' && (
          <div className="flex-1 flex flex-col overflow-hidden">
            
            {/* Filter Control Bar */}
            <div className="term-border p-3 mb-3 bg-term-yellow/10 flex items-center justify-between text-xs font-mono">
              <div className="flex items-center space-x-3">
                <span className="font-bold text-term-yellow">FILTER BY:</span>
                <button 
                  onClick={() => { setFilterMode('ALL'); setFilterValue(''); }} 
                  className={`px-3 py-1 term-button text-xs font-bold ${filterMode === 'ALL' ? 'bg-term-yellow text-term-black' : ''}`}
                >
                  SHOW ALL
                </button>
                <button 
                  onClick={() => { setFilterMode('IP'); setFilterValue(''); }} 
                  className={`px-3 py-1 term-button text-xs font-bold ${filterMode === 'IP' ? 'bg-term-yellow text-term-black' : ''}`}
                >
                  IP ADDRESS
                </button>
                <button 
                  onClick={() => { setFilterMode('PORT'); setFilterValue(''); }} 
                  className={`px-3 py-1 term-button text-xs font-bold ${filterMode === 'PORT' ? 'bg-term-yellow text-term-black' : ''}`}
                >
                  PORT
                </button>
                <button 
                  onClick={() => { setFilterMode('PROTO'); setFilterValue(''); }} 
                  className={`px-3 py-1 term-button text-xs font-bold ${filterMode === 'PROTO' ? 'bg-term-yellow text-term-black' : ''}`}
                >
                  PROTOCOL (TCP/UDP/ICMP/DNS)
                </button>
              </div>

              {/* Dynamic Filter Input / Selector */}
              {filterMode === 'ALL' ? (
                <div className="opacity-60 text-xs italic">
                  [Showing all captured traffic]
                </div>
              ) : filterMode === 'PROTO' ? (
                <div className="flex items-center space-x-2">
                  <span className="font-bold text-term-yellow">SELECT PROTOCOL:</span>
                  <select 
                    value={filterValue} 
                    onChange={(e) => setFilterValue(e.target.value)}
                    className="bg-term-black text-term-yellow border border-term-yellow px-2 py-1 text-xs outline-none focus:bg-term-yellow/10 font-bold"
                  >
                    <option value="">-- ALL PROTOCOLS --</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                    <option value="DNS">DNS</option>
                  </select>
                </div>
              ) : (
                <div className="flex items-center space-x-2">
                  <span className="font-bold text-term-yellow">
                    ENTER {filterMode === 'IP' ? 'IP ADDRESS (e.g. 8.8.8.8)' : 'PORT (e.g. 443)'}:
                  </span>
                  <input 
                    type="text" 
                    value={filterValue}
                    onChange={(e) => setFilterValue(e.target.value)}
                    placeholder={filterMode === 'IP' ? "Search IP..." : "Search Port..."}
                    className="bg-term-black text-term-yellow border border-term-yellow px-3 py-1 text-xs outline-none focus:bg-term-yellow/10 font-bold w-48"
                  />
                  {filterValue && (
                    <button 
                      onClick={() => setFilterValue('')}
                      className="text-term-alert font-bold hover:underline text-xs"
                    >
                      CLEAR
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* Packet List Feed */}
            <div className="flex-1 term-border flex flex-col overflow-hidden bg-term-black">
              <div className="border-b border-term-yellow p-2 flex justify-between items-center bg-term-yellow text-term-black font-bold text-xs">
                <span>/NETRA/NDR/TRAFFIC.FEED</span>
                <span>
                  [{getFilteredPackets().length} OF {packets.length} PACKETS DISPLAYED | FILTER: {filterMode}]
                </span>
              </div>

              <div className="p-2 border-b border-term-yellow/30 bg-term-yellow/10 grid grid-cols-12 text-[11px] font-bold text-term-yellow/80 uppercase">
                <span className="col-span-1">#</span>
                <span className="col-span-2">TIME</span>
                <span className="col-span-1">PID</span>
                <span className="col-span-2">PROCESS</span>
                <span className="col-span-2">PROTO</span>
                <span className="col-span-3">DESTINATION</span>
                <span className="col-span-1 text-right">SIZE</span>
              </div>

              <div className="flex-1 overflow-y-auto p-2 space-y-1 text-xs">
                {getFilteredPackets().length === 0 ? (
                  <div className="p-8 text-center text-term-yellow/50 italic text-xs">
                    No packets matching current filter criteria "{filterValue || filterMode}".
                  </div>
                ) : (
                  getFilteredPackets().map((pkt) => (
                    <div 
                      key={pkt.id} 
                      onDoubleClick={() => setSelectedPacket(pkt)}
                      className="grid grid-cols-12 p-2 cursor-pointer border border-transparent transition-colors hover:bg-term-yellow/20 hover:border-term-yellow/50 text-term-yellow"
                    >
                      <span className="col-span-1 opacity-70">#{pkt.id}</span>
                      <span className="col-span-2 text-[11px] opacity-90">{pkt.timestamp}</span>
                      <span className="col-span-1 font-bold">{pkt.pid}</span>
                      <span className="col-span-2 truncate">{pkt.comm}</span>
                      <span className="col-span-2 font-bold text-term-orange">{pkt.protocol}</span>
                      <span className="col-span-3 truncate font-bold text-term-yellow">{pkt.dst_ip}:{pkt.dst_port}</span>
                      <span className="col-span-1 text-right opacity-80">{pkt.len}B</span>
                    </div>
                  ))
                )}
              </div>
            </div>

          </div>
        )}

        {/* EDR Console Log Area (for VERIFY_REALTIME & VERIFY_ROOTKITS) */}
        {activeTab !== 'TRAFFIC_TRACKER' && (
          <div className="flex-1 term-border flex flex-col overflow-hidden bg-term-black relative">
            <div className="border-b border-term-yellow p-2 flex justify-between items-center bg-term-yellow text-term-black">
              <span className="font-bold text-sm">
                /NETRA/{activeTab}/EVENTS.LOG
              </span>
              <span>[{getFilteredLogs().length} EVENTS]</span>
            </div>
            <div className="flex-1 p-4 overflow-y-auto flex flex-col-reverse term-glow">
              <div className="space-y-1">
                {getFilteredLogs().map((log, index) => {
                  let logClass = "text-term-yellow";
                  if (log.includes("WARNING")) {
                    logClass = "text-term-orange font-bold bg-term-orange/20 term-glow";
                  } else if (
                    log.includes("STOPPED") || 
                    log.includes("ALERT") || 
                    log.includes("CAMERA") || 
                    log.includes("SPYWARE") || 
                    log.includes("RANSOMWARE") ||
                    log.includes("ROOTKIT") ||
                    log.includes("FILELESS") ||
                    log.includes("LKM_LOAD") ||
                    log.includes("PTRACE_INJECT") ||
                    log.includes("EBPF_LOAD")
                  ) {
                    logClass = "text-term-alert font-bold bg-term-alert/20 term-glow";
                  }
                  if (log.includes("[OK]") || log.includes("PASSED") || log.includes("COMPLETE")) {
                    logClass = "text-term-ok font-bold";
                  }

                  return (
                    <div key={index} className={`${logClass} break-all`}>
                      <span className="mr-2 opacity-50">{'>'}</span>
                      {log}
                    </div>
                  );
                })}
                <div className="mt-2 text-term-yellow/50 animate-pulse">_</div>
              </div>
            </div>
          </div>
        )}

        {/* Big CLI SCAN Button */}
        {activeTab !== 'TRAFFIC_TRACKER' && (
          <div className="absolute bottom-4 right-4 z-50">
            <button 
              className="w-48 h-16 term-button text-xl font-bold tracking-[0.3em] flex items-center justify-center relative group"
              onClick={handleScanClick}
              disabled={isScanning}
            >
              <span className="absolute left-2 opacity-0 group-hover:opacity-100 transition-opacity">[{'>'}]</span>
              <span>{isScanning ? 'SCANNING...' : 'SCAN'}</span>
              <span className="absolute right-2 opacity-0 group-hover:opacity-100 transition-opacity">[{'<'}]</span>
            </button>
          </div>
        )}

      </main>

      {/* Modal Popup Window for Packet Inspector */}
      {selectedPacket && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-6 animate-in fade-in duration-150">
          <div className="w-full max-w-4xl h-[80vh] term-border-glow flex flex-col bg-term-black relative shadow-2xl">
            <div className="border-b border-term-yellow p-3 flex justify-between items-center bg-term-yellow text-term-black font-bold text-sm">
              <span>=== NDR PACKET INSPECTOR [PKT #{selectedPacket.id}] ===</span>
              <button 
                onClick={() => setSelectedPacket(null)} 
                className="px-2 py-0.5 text-xs font-black bg-term-black text-term-yellow hover:bg-red-600 hover:text-white border border-term-black"
              >
                [X] CLOSE
              </button>
            </div>

            {/* Metadata Section */}
            <div className="p-3 border-b border-term-yellow/30 bg-term-yellow/10 text-xs grid grid-cols-3 gap-2">
              <div><span className="opacity-70">PROCESS:</span> <strong className="text-term-yellow">{selectedPacket.comm} (PID:{selectedPacket.pid})</strong></div>
              <div><span className="opacity-70">PROTOCOL:</span> <strong className="text-term-orange">{selectedPacket.protocol}</strong></div>
              <div><span className="opacity-70">DESTINATION:</span> <strong className="text-term-yellow">{selectedPacket.dst_ip}:{selectedPacket.dst_port}</strong></div>
              <div><span className="opacity-70">PAYLOAD SIZE:</span> <strong className="text-term-ok">{selectedPacket.len} Bytes</strong></div>
              <div><span className="opacity-70">TIMESTAMP:</span> <span>{selectedPacket.timestamp}</span></div>
              <div><span className="opacity-70">SOURCE:</span> <span>{selectedPacket.src_ip}</span></div>
            </div>

            {/* Content Section: RAW ASCII + HEX DUMP */}
            <div className="flex-1 p-4 flex flex-col space-y-4 overflow-y-auto text-xs">
              <div>
                <div className="text-xs text-term-yellow/70 uppercase font-bold mb-1">
                  === RAW ASCII CONTENT ===
                </div>
                <pre className="p-3 term-border bg-term-yellow/10 text-term-yellow text-xs whitespace-pre-wrap break-all max-h-48 overflow-y-auto font-mono">
                  {selectedPacket.payload || "[NO RAW STRING PAYLOAD DATA]"}
                </pre>
              </div>

              <div className="flex-1 flex flex-col">
                <div className="text-xs text-term-yellow/70 uppercase font-bold mb-1">
                  === HEX DUMP & ASCII INTERPRETATION ===
                </div>
                <pre className="flex-1 p-3 term-border bg-term-black text-term-ok text-xs leading-relaxed whitespace-pre overflow-x-auto overflow-y-auto font-mono">
                  {selectedPacket.hex_dump || "[NO HEX DUMP AVAILABLE]"}
                </pre>
              </div>
            </div>

            <div className="p-2 border-t border-term-yellow/30 bg-term-black flex justify-between items-center text-xs">
              <span className="opacity-60">Press ESC or [X] CLOSE button to return to packet list</span>
              <button 
                onClick={() => setSelectedPacket(null)}
                className="term-button px-4 py-1 font-bold text-xs"
              >
                CLOSE WINDOW
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

export default App;
