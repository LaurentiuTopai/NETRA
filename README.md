# NETRA — EDR/NDR bazat pe eBPF cu UI în Go (Wails)

## Descriere generală

NETRA este un sistem de detecție și răspuns la nivel de endpoint (EDR — *Endpoint Detection and Response*), cu extindere planificată către detecție la nivel de rețea (NDR — *Network Detection and Response*). Sistemul folosește **eBPF** pentru colectarea de evenimente direct din kernel-ul Linux (creare de procese, operații pe fișiere), un modul de **corelare și decizie în user-space (C)**, un mecanism de **răspuns automat** (izolare de proces), și o **interfață grafică desktop** construită în Go, cu ajutorul framework-ului **Wails**.

Proiectul este dezvoltat ca parte a lucrării de licență, cu scopul de a demonstra o arhitectură completă de detecție a comportamentului malițios (cu accent pe ransomware) — de la colectarea datelor la nivel de kernel, până la reacția automată și vizualizarea în timp real pentru utilizator.

---

## Arhitectură

```
┌─────────────────────────────────────────────────────────────┐
│                         KERNEL SPACE                        │
│                                                               │
│   edr.bpf.c              filer.bpf.c                        │
│   (tracepoint execve)    (tracepoint openat)                │
│         │                       │                            │
│         └──────────┬────────────┘                            │
│                     │  (BPF ring buffers)                    │
└─────────────────────┼────────────────────────────────────────┘
                       │
┌─────────────────────┼────────────────────────────────────────┐
│                  USER SPACE (C)                              │
│                     │                                         │
│                edr.c (orchestrator)                          │
│         ┌───────────┼────────────┐                           │
│         │           │            │                           │
│   add_or_update  register_file_write                         │
│   _process()      (detectie ransomware, fereastra de timp)   │
│         │           │                                         │
│         └─────hashmap (uthash)──┘                             │
│                     │                                         │
│              response.c (SIGSTOP / SIGKILL / forensics)      │
└─────────────────────┼────────────────────────────────────────┘
                       │  (planificat: JSON pe stdout / socket)
┌─────────────────────┼────────────────────────────────────────┐
│                GO + WAILS (UI Desktop)                       │
│                     │                                         │
│              collector (os/exec + parsare evenimente)        │
│                     │                                         │
│              UI (HTML/CSS/JS randat nativ, fara Electron)     │
└────────────────────────────────────────────────────────────────┘
```

---

## Componente

### 1. `edr.bpf.c` / `edr.c` — Detecție de procese noi
- Program eBPF atașat pe tracepoint-ul `sys_enter_execve`.
- Capturează PID, PPID și numele comenzii (`comm`) pentru fiecare proces nou lansat.
- Trimite evenimentele către user-space printr-un **ring buffer** (`BPF_MAP_TYPE_RINGBUF`).
- În user-space, evenimentele sunt stocate într-un hashmap (`uthash`), indexat după PID.

### 2. `filer.bpf.c` / `filer.c` — Detecție de operații pe fișiere
- Program eBPF atașat pe tracepoint-ul `sys_enter_openat`.
- Capturează PID, `comm`, calea fișierului (`filename`) și flag-urile de deschidere (`O_WRONLY`, `O_RDWR`, `O_CREAT`, etc.).
- Rulează inițial ca binar independent (`filer`), apoi integrat direct în `edr` printr-un al doilea ring buffer atașat cu `ring_buffer__add()`.

### 3. Motorul de detecție (în `edr.c`)
- Corelează evenimentele de scriere de fișiere per proces, într-o **fereastră de timp** (`TIME_WINDOW_SEC`).
- Dacă un proces depășește un prag de scrieri (`MAX_WRITES_ALLOWED`) în interiorul ferestrei, se declanșează o alertă — comportament caracteristic ransomware-ului (criptare/rescriere în masă a fișierelor).
- **Whitelisting** pe două niveluri, pentru reducerea fals-pozitivelor:
  - pe **path** de fișier (ex: `/tmp/`, `/proc/`, `.cache/`) — zone care nu sunt ținte tipice de ransomware;
  - pe **nume de proces/thread** (`comm`) — pentru procese de sistem/browser foarte active dar legitime.

### 4. `response.c` / `response.h` — Modulul de răspuns
- La declanșarea unei alerte, procesul suspect este **izolat** (nu omorât direct) prin semnalul `SIGSTOP`, pentru a permite investigație manuală ulterioară fără a distruge dovezi sau a întrerupe brutal un posibil fals-pozitiv.
- Prevăzut și `kill_malicious_process()` (SIGKILL), pentru cazurile confirmate.
- Prevăzut (neimplementat încă) `dump_process_forensics()` — extragere de detalii despre proces din `/proc/<pid>/` (binar executat, linie de comandă, fișiere deschise, working directory) pentru investigație manuală.

### 5. UI — Go + Wails
- Aplicație desktop nativă (nu web, nu Electron) — randare printr-un webview nativ (WebKitGTK pe Linux).
- Va centraliza evenimentele provenite din modulele C (EDR, viitor: NDR/network), afișându-le live utilizatorului.
- Arhitectură plănuită: fiecare sursă de evenimente (EDR, network, viitoare module) rulează ca subproces, gestionat de un goroutine dedicat; evenimentele sunt trimise printr-un canal central Go către interfață.

---

## Structura proiectului

```
NETRA/
├── edr.bpf.c            # program eBPF - detectie execve
├── edr.c                # orchestrator user-space: hashmap, detectie, alerte
├── filer.bpf.c           # program eBPF - detectie openat
├── filer.c               # binar independent pentru testare filer
├── response.c            # modul de raspuns (quarantine/kill/forensics)
├── response.h
├── uthash.h               # librarie hashmap (header-only)
├── vmlinux.h              # tipuri kernel, generate pentru CO-RE
├── Makefile
└── UI/
    └── netra-ui/          # proiect Wails (Go + frontend web)
        ├── app.go
        ├── main.go
        ├── go.mod
        ├── frontend/
        └── build/bin/netra-ui   # binar compilat final
```

---

## Cerințe de sistem

- Linux cu suport eBPF (kernel ≥ 5.8 recomandat pentru CO-RE)
- `clang`, `bpftool`, `libbpf-dev`
- Pentru UI: `Go` ≥ 1.21, `Node.js`/`npm`, `libgtk-3-dev`, `libwebkit2gtk-4.1-dev` (pe Ubuntu 24.04+, atenție la denumirea pachetului — vezi secțiunea de probleme cunoscute din istoricul de dezvoltare)

## Compilare și rulare

### Partea de EDR (C/eBPF)

```bash
make clean
make
sudo ./edr
```

### Partea de UI (Go/Wails)

```bash
cd UI/netra-ui
wails dev -tags webkit2_41          # development, cu hot-reload
# sau
wails build -tags webkit2_41        # build de productie
./build/bin/netra-ui
```

---

## Stadiu curent (versiune de lucru)

- [x] Detecție procese noi (execve)
- [x] Detecție operații de scriere pe fișiere (openat)
- [x] Corelare pe fereastră de timp + prag de scrieri
- [x] Whitelisting pe path și pe comm
- [x] Răspuns automat (SIGSTOP) la depășirea pragului
- [x] Aplicație desktop funcțională (schelet, Wails)
- [ ] Comunicare structurată (JSON) între modulele C și UI
- [ ] Interfață finală cu evenimente live, alerte, istoric
- [ ] Modul NDR (network detection)
- [ ] Forensics detaliat per proces (`/proc/<pid>/`)
- [ ] Detecție redenumire/criptare fișiere (rename/renameat)

Pentru detalii pas-cu-pas despre dezvoltare, bug-uri întâlnite și cum au fost rezolvate, vezi `DEVELOPMENT_HISTORY.md`.
