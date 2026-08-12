#!/bin/bash
# Script de pornire rapida pentru executabilul compilat NETRA UI

xhost +local:root >/dev/null 2>&1
cd "$(dirname "$0")"
sudo -E ./build/bin/netra-ui
