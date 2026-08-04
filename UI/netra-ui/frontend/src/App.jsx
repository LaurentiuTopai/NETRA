import React, { useState, useEffect } from 'react';
import logoUrl from './assets/logo.jpg';

const SidebarItem = ({ icon, label, active }) => (
  <button className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-300 ${active ? 'bg-cyber-yellow/10 text-cyber-yellow border border-cyber-yellow/30 glow-border' : 'text-slate-500 hover:bg-white/5 hover:text-slate-300'}`}>
    <span className="text-xl">{icon}</span>
    <span className="font-medium tracking-wide">{label}</span>
  </button>
);

const StatCard = ({ title, value, status, icon }) => (
  <div className="glass-panel p-5 rounded-xl flex items-center justify-between border-l-4 border-l-cyber-yellow relative overflow-hidden group">
    <div>
      <span className="text-xs text-slate-500 font-bold tracking-widest uppercase mb-1 block">{title}</span>
      <span className="text-3xl font-black text-white group-hover:text-cyber-yellow transition-colors">{value}</span>
    </div>
    <div className="text-3xl text-cyber-yellow/50 group-hover:text-cyber-yellow/80 transition-colors">
      {icon}
    </div>
  </div>
);

function App() {
  const [activeTab, setActiveTab] = useState('EDR Console');
  const [logs, setLogs] = useState([
    "NETRA EDR SYSTEM INITIALIZED...",
    "LOADING KERNEL MODULES... OK",
    "HOOKING SYSTEM CALLS... OK",
    "ESTABLISHING SECURE CONNECTION TO TELEMETRY SERVER...",
    "CONNECTION ESTABLISHED. WAITING FOR EVENTS...",
  ]);

  // Simulate incoming logs
  useEffect(() => {
    const interval = setInterval(() => {
      const mockLogs = [
        "[INFO] Process 'svchost.exe' executed successfully.",
        "[WARN] Suspicious registry modification detected in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "[INFO] Routine filesystem integrity check passed.",
        "[ALERT] Unauthorized execution attempt blocked: C:\\Users\\Public\\malware.exe",
        "[INFO] Network connection from 192.168.1.15 allowed on port 443.",
      ];
      const randomLog = mockLogs[Math.floor(Math.random() * mockLogs.length)];
      setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${randomLog}`].slice(-100)); // keep last 100
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-cyber-dark text-slate-200 flex overflow-hidden font-sans selection:bg-cyber-yellow/30 selection:text-white">
      
      {/* Sidebar */}
      <aside className="w-64 glass-panel border-r border-white/5 flex flex-col relative z-20">
        <div className="p-6 flex flex-col items-center border-b border-white/5">
          <div className="relative mb-4 group cursor-pointer">
            <img src={logoUrl} alt="NETRA Logo" className="w-20 h-20 rounded-full object-cover border-2 border-cyber-yellow shadow-[0_0_20px_rgba(234,179,8,0.4)] group-hover:shadow-[0_0_30px_rgba(234,179,8,0.7)] transition-all" />
            <div className="absolute inset-0 rounded-full border border-cyber-yellow/30 animate-ping"></div>
          </div>
          <div className="text-center">
            <h1 className="text-2xl font-black tracking-[0.3em] text-cyber-yellow glow-text">NETRA</h1>
            <p className="text-[0.65rem] uppercase tracking-[0.4em] text-slate-500 font-bold mt-1">EDR Core</p>
          </div>
        </div>

        <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto">
          <SidebarItem icon="⚡" label="EDR Console" active={activeTab === 'EDR Console'} />
          <SidebarItem icon="🔍" label="Malware Scans" active={activeTab === 'Scans'} />
          <SidebarItem icon="🛡" label="Rootkit Detection" active={activeTab === 'Rootkit'} />
          <SidebarItem icon="⚠" label="Alert History" active={activeTab === 'Alerts'} />
        </nav>

        <div className="p-4 border-t border-white/5">
          <SidebarItem icon="⚙" label="Agent Settings" active={activeTab === 'Settings'} />
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col relative h-screen overflow-hidden bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-cyber-gray to-black">
        
        {/* Top Header */}
        <header className="h-16 border-b border-white/5 flex items-center justify-between px-8 z-10 bg-black/50 backdrop-blur-sm">
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 rounded-full bg-cyber-yellow animate-pulse shadow-[0_0_8px_rgba(234,179,8,0.8)]"></div>
            <span className="text-xs font-mono text-cyber-yellow tracking-widest uppercase">System Protected</span>
          </div>
          <div className="text-xs font-mono text-slate-500">
            HOST: SEC-WIN-001 | IP: 10.0.0.42 | OS: Windows 11 Enterprise
          </div>
        </header>

        {/* Dashboard Grid */}
        <div className="flex-1 p-6 flex flex-col gap-6 overflow-hidden">
          
          {/* Stats Row */}
          <div className="grid grid-cols-4 gap-6 shrink-0">
            <StatCard title="Active Processes" value="142" icon="⚙" />
            <StatCard title="Files Scanned" value="24.8k" icon="📂" />
            <StatCard title="Threats Blocked" value="7" icon="⚠" />
            <StatCard title="Network Conns" value="38" icon="🕸" />
          </div>

          {/* Central Console Log */}
          <div className="flex-1 glass-panel rounded-xl border border-white/5 flex flex-col overflow-hidden relative">
            <div className="bg-black/60 px-4 py-2 border-b border-white/5 flex items-center justify-between">
              <span className="text-sm font-bold text-cyber-yellow uppercase tracking-widest">Live Security Event Log</span>
              <div className="flex space-x-2">
                <div className="w-3 h-3 rounded-full bg-red-500/20 border border-red-500/50"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500/20 border border-yellow-500/50"></div>
                <div className="w-3 h-3 rounded-full bg-green-500/20 border border-green-500/50"></div>
              </div>
            </div>
            <div className="flex-1 bg-black p-4 font-mono text-sm overflow-y-auto relative scanlines flex flex-col-reverse">
              {/* Logs */}
              <div className="space-y-1">
                {logs.map((log, index) => {
                  let color = "text-slate-300";
                  if (log.includes("[WARN]")) color = "text-cyber-yellow";
                  if (log.includes("[ALERT]") || log.includes("BLOCKED")) color = "text-red-500 glow-text drop-shadow-[0_0_5px_rgba(239,68,68,0.8)]";
                  if (log.includes("OK") || log.includes("ESTABLISHED")) color = "text-green-400";
                  
                  return (
                    <div key={index} className={`${color} leading-relaxed`}>
                      <span className="text-slate-600 select-none mr-2">{'>'}</span>
                      {log}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Floating SCAN button */}
        <div className="absolute bottom-10 right-10 z-50">
          <button className="group relative w-48 h-16 bg-gradient-to-b from-zinc-800 to-black text-cyber-yellow font-black text-2xl tracking-[0.2em] shadow-[0_0_20px_rgba(234,179,8,0.2)] hover:shadow-[0_0_35px_rgba(234,179,8,0.6)] transition-all transform hover:-translate-y-1 active:translate-y-1 flex items-center justify-center overflow-hidden border-t-4 border-t-cyber-yellow border-b-4 border-b-black border-x-2 border-x-zinc-800 rounded-sm">
            <div className="absolute inset-0 bg-cyber-yellow/10 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
            {/* Inner glow line for that old school 3D look */}
            <div className="absolute top-0 left-0 right-0 h-[1px] bg-white/20"></div>
            <span className="relative z-10 flex items-center justify-center drop-shadow-md">
              <span>SCAN</span>
            </span>
          </button>
        </div>

      </main>
    </div>
  );
}

export default App;
