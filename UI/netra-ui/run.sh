#!/bin/bash
# Script de pornire rapida pentru NETRA UI (Wails + eBPF Kernel Engine)

# 1. Permite accesul grafic pentru root
xhost +local:root >/dev/null 2>&1

# 2. Navigheaza in directorul proiectului
cd "$(dirname "$0")"

# 3. Ruleaza Wails Dev cu drepturi de root si tag-ul pentru WebKit 4.1
sudo -E ~/go/bin/wails dev -tags webkit2_41
