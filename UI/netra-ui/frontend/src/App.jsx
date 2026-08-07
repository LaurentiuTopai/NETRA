import React, { useState, useEffect } from 'react';
import { EventsOn } from '../wailsjs/runtime/runtime';

const eyeAscii = `
⠀⠀⠀⠀⠀⠀⣀⠄⠤⠄⠤⠤⠤⠠⣀⣀⠀⠀⠀⠀⠀⠀
⠀⠀⡀⡠⠂⠁⠀⣀⣔⡖⠦⠦⠤⣄⣀⠀⠉⠒⠆⣀⠀⠀
⢀⠎⠀⡀⠔⡪⠋⠁⠀⡀⡀⠀⠀⠀⠈⡏⠓⠆⠤⣀⣑⡆
⠫⡂⠁⠀⢸⠀⠀⠀⢸⣟⡟⠃⠀⠀⠀⡇⠀⠀⣀⠴⠢⠋
⠀⠈⠀⠠⠀⡑⢄⣀⠀⠀⠀⠀⢀⣀⡜⡄⠒⣩⠀⠀⡃⠀
⠀⠀⠀⠀⠀⠈⠉⠒⠛⠛⠛⡏⠋⠉⣀⢿⣠⢟⠀⣄⡃⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠓⠊⠀⠀⠀⠔⠀⡇⠁⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣇⣀⠅⠀⠀
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
  const [activeTab, setActiveTab] = useState('EDR_CONSOLE');
  const [isScanning, setIsScanning] = useState(false);
  const [threatCount, setThreatCount] = useState(0);
  const [logs, setLogs] = useState([
    "[SYSTEM] NETRA eBPF KERNEL HOOK INITIALIZED...",
    "[SYSTEM] TELEMETRY MODULE LOADED [OK]",
    "[SYSTEM] AWAITING SECURITY EVENTS...",
  ]);

  useEffect(() => {
    const cancel = EventsOn("edr:alert", (alert) => {
      const logMessage = `[${alert.timestamp}] [${alert.type}] PID:${alert.pid} (${alert.comm}) - ${alert.message}`;

      setLogs((prev) => [...prev, logMessage].slice(-100));

      if (alert.type.includes("STOPPED") || alert.type.includes("WARNING")) {
        setThreatCount((prev) => prev + 1);
      }
    });

    return () => {
      if (typeof cancel === 'function') cancel();
    };
  }, []);

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
            <StatBlock label="ACTIVE_PROCS" value="142" />
            <StatBlock label="SCANNED_FILES" value="24,809" />
            <StatBlock label="THREATS_BLOCKED" value={String(threatCount).padStart(3, '0')} />
            <StatBlock label="NET_CONNS" value="038" />
          </div>
        </div>

        <nav className="flex-1 p-4 overflow-y-auto">
          <div className="mb-2 text-xs text-term-yellow/50 font-bold">=== MAIN MENU ===</div>
          <SidebarButton label="[1] EDR_CONSOLE" active={activeTab === 'EDR_CONSOLE'} onClick={() => setActiveTab('EDR_CONSOLE')} />
          <SidebarButton label="[2] RUN_SCANS" active={activeTab === 'RUN_SCANS'} onClick={() => setActiveTab('RUN_SCANS')} />
          <SidebarButton label="[3] ROOTKIT_DETECTOR" active={activeTab === 'ROOTKIT_DETECTOR'} onClick={() => setActiveTab('ROOTKIT_DETECTOR')} />
          <SidebarButton label="[4] ALERT_HISTORY" active={activeTab === 'ALERT_HISTORY'} onClick={() => setActiveTab('ALERT_HISTORY')} />
          
          <div className="mt-8 mb-2 text-xs text-term-yellow/50 font-bold">=== SESSION ===</div>
          <SidebarButton label="[8] AGENT_CONFIG" active={activeTab === 'AGENT_CONFIG'} onClick={() => setActiveTab('AGENT_CONFIG')} />
          <SidebarButton label="[9] DISCONNECT" active={activeTab === 'DISCONNECT'} onClick={() => setActiveTab('DISCONNECT')} />
        </nav>
      </aside>

      {/* Main Terminal View */}
      <main className="flex-1 flex flex-col relative m-4 ml-0 h-[calc(100vh-2rem)] z-10">
        
        {/* Top NETRA ASCII Header */}
        <header className="mb-4 flex flex-col items-center justify-center pt-2">
          <pre className="text-sm md:text-base leading-tight font-black term-glow whitespace-pre text-center">
            {netraAscii}
          </pre>
        </header>

        {/* Top Info Bar */}
        <div className="term-border p-2 mb-4 bg-term-black flex justify-between items-center text-xs">
          <div>HOST: SEC-LINUX-01 | IP: 127.0.0.1 | OS: LINUX_eBPF_KERNEL</div>
          <div className="animate-pulse">_ TERMINAL ACTIVE _</div>
        </div>

        {/* Console Log Area */}
        <div className="flex-1 term-border flex flex-col overflow-hidden bg-term-black relative">
          <div className="border-b border-term-yellow p-2 flex justify-between items-center bg-term-yellow text-term-black">
            <span className="font-bold text-sm">/NETRA/EDR/LIVE_EVENTS.LOG</span>
            <span>[X]</span>
          </div>
          <div className="flex-1 p-4 overflow-y-auto flex flex-col-reverse term-glow">
            <div className="space-y-1">
              {logs.map((log, index) => {
                let logClass = "text-term-yellow";
                if (log.includes("WARNING")) {
                  logClass = "text-term-orange font-bold bg-term-orange/20 term-glow";
                } else if (log.includes("STOPPED") || log.includes("ALERT") || log.includes("CAMERA") || log.includes("SPYWARE")) {
                  logClass = "text-term-alert font-bold bg-term-alert/20 term-glow";
                }
                if (log.includes("[OK]") || log.includes("PASSED")) logClass = "text-term-ok";

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

        {/* Big CLI SCAN Button */}
        <div className="absolute bottom-4 right-4 z-50">
          <button 
            className="w-48 h-16 term-button text-xl font-bold tracking-[0.3em] flex items-center justify-center relative group"
            onClick={() => {
              const newScanState = !isScanning;
              setIsScanning(newScanState);
              const now = new Date().toLocaleTimeString();
              if (newScanState) {
                setLogs(prev => [...prev, `[${now}] !! [ALERT] INITIATING DEEP SYSTEM SCAN... THEME OVERRIDE: ACTIVE`].slice(-100));
                
                // Apelăm funcția din backend (Go)
                if (window.go && window.go.main && window.go.main.App) {
                  window.go.main.App.StartScan();
                } else {
                  console.warn("Backend-ul Go nu este încărcat, verifică Wails.");
                }
              } else {
                setLogs(prev => [...prev, `[${now}] [INFO] SCAN ABORTED. RETURNING TO STANDARD MONITORING.`].slice(-100));
              }
            }}
          >
            <span className="absolute left-2 opacity-0 group-hover:opacity-100 transition-opacity">[{'>'}]</span>
            <span>{isScanning ? 'STOP' : 'SCAN'}</span>
            <span className="absolute right-2 opacity-0 group-hover:opacity-100 transition-opacity">[{'<'}]</span>
          </button>
        </div>

      </main>
    </div>
  );
}

export default App;
