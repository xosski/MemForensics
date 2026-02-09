# Advanced Memory Forensic Toolkit - Deployment Guide

## Overview
Complete deployment and installation instructions for the Advanced Memory Forensic Toolkit across Windows and Linux systems.

---

## Pre-Deployment Checklist

- [ ] Python 3.8+ installed
- [ ] Internet connection available
- [ ] 2GB+ free disk space
- [ ] Administrator/Root access (for some features)
- [ ] 4GB+ system RAM
- [ ] Git installed (for cloning)

---

## Installation Methods

## Method 1: Automated Setup (Recommended)

### Windows
```bash
# 1. Open Command Prompt as Administrator
# 2. Navigate to toolkit directory
cd C:\Users\YourUser\Desktop\X12\MemForensics

# 3. Run setup script
python setup.py

# 4. Follow prompts
```

### Linux
```bash
# 1. Navigate to toolkit directory
cd ~/Desktop/X12/MemForensics

# 2. Run setup script with sudo
sudo python3 setup.py

# 3. Follow prompts
```

**What setup.py does:**
- Verifies all required files
- Installs Python dependencies
- Checks system tools
- Creates launch shortcuts
- Generates configuration files

---

## Method 2: Manual Installation

### Windows Step-by-Step

**Step 1: Install Python 3.8+**
```bash
# Download from python.org or verify installation
python --version
```

**Step 2: Install Dependencies**
```bash
# Open Command Prompt as Administrator
cd C:\Path\To\MemForensics
pip install -r requirements.txt

# Install optional Volatility3
pip install volatility3
```

**Step 3: Verify Installation**
```bash
python main.py
```

**Step 4: (Optional) Install WinPmem**
```
# Download from: https://github.com/Velocidex/WinPmem
# Extract winpmem_mini_x64.exe to:
# - Program Files\WinPmem\
# - Or MemForensics directory
```

### Linux Step-by-Step

**Step 1: Install Python 3.8+**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip
python3 --version
```

**Step 2: Install System Tools**
```bash
sudo apt-get install libssl-dev python3-dev
```

**Step 3: Install Dependencies**
```bash
cd ~/Desktop/X12/MemForensics
pip3 install -r requirements.txt
```

**Step 4: Install Optional Tools**
```bash
# Volatility3 (for advanced analysis)
pip3 install volatility3

# YARA (for signature matching)
sudo apt-get install yara python3-yara

# Capstone (for disassembly)
pip3 install capstone
```

**Step 5: Verify Installation**
```bash
sudo python3 main.py
```

---

## Docker Deployment (Advanced)

### Create Dockerfile

```dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libssl-dev \
    yara \
    volatility3 \
    && rm -rf /var/lib/apt/lists/*

# Copy toolkit
WORKDIR /app
COPY . /app

# Install Python dependencies
RUN pip install -r requirements.txt

# Create non-root user
RUN useradd -m forensics
USER forensics

# Run GUI (requires X11 forwarding)
CMD ["python3", "main.py"]
```

### Build and Run

```bash
# Build image
docker build -t memforensics .

# Run with GUI (Linux)
docker run -it --rm \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v /home/user/evidence:/evidence \
  memforensics

# Run without GUI (headless)
docker run -it --rm \
  -v /evidence:/evidence \
  memforensics python3 advanced_scanner.py
```

---

## Portable Installation (USB Drive)

### Windows Portable

**Step 1: Create USB Structure**
```
E:\MemForensics\
├── python-embedded\        (Python 3.9 embedded)
├── toolkit\                (All Python modules)
├── run.bat                 (Launch script)
└── README.txt
```

**Step 2: Download Embedded Python**
- Download from python.org (embedded release)
- Extract to python-embedded\
- Extract libs from "Windows embeddable package"

**Step 3: Install Dependencies to USB**
```bash
E:\python-embedded\python.exe -m pip install -r requirements.txt -t toolkit\
```

**Step 4: Create run.bat**
```batch
@echo off
set PYTHONPATH=toolkit
python-embedded\python.exe toolkit\main.py
pause
```

### Linux Portable

**Step 1: Create USB Structure**
```
/mnt/usb/MemForensics/
├── python-venv/        (Virtual environment)
├── toolkit/            (All modules)
├── run.sh             (Launch script)
└── README.txt
```

**Step 2: Create Virtual Environment**
```bash
mkdir -p /mnt/usb/MemForensics
python3 -m venv /mnt/usb/MemForensics/python-venv
source /mnt/usb/MemForensics/python-venv/bin/activate
pip install -r requirements.txt
```

**Step 3: Create run.sh**
```bash
#!/bin/bash
cd "$(dirname "$0")"
source python-venv/bin/activate
python3 main.py
```

---

## Cloud Deployment (AWS/Azure)

### AWS EC2 Setup

**Step 1: Launch Instance**
```bash
# Use Ubuntu 20.04 LTS AMI
# Instance type: t3.large (recommended)
# Security group: Allow RDP/SSH + VNC for GUI
```

**Step 2: Install on Instance**
```bash
ssh -i key.pem ubuntu@instance-ip

sudo apt-get update
sudo apt-get install python3 python3-pip volatility3

# Copy toolkit
scp -r -i key.pem MemForensics ubuntu@instance-ip:~/

# Install dependencies
cd ~/MemForensics
pip3 install -r requirements.txt
```

**Step 3: Run via VNC (GUI)**
```bash
# Install VNC
sudo apt-get install tightvncserver
vncserver :1

# Connect with VNC client to instance-ip:5901
# Run toolkit
python3 main.py &
```

### Azure Container Instances

```bash
# Build and push to Azure Container Registry
az acr build --registry myregistry --image memforensics:latest .

# Run container
az container create \
  --resource-group mygroup \
  --name memforensics \
  --image myregistry.azurecr.io/memforensics:latest \
  --restart-policy Never
```

---

## Network Installation (Corporate)

### Network Share Setup (Windows)

**Step 1: Create Share on Server**
```powershell
# Create shared folder
New-Item -Path "\\server\MemForensics" -ItemType Directory

# Copy toolkit files
Copy-Item -Path "MemForensics\*" -Destination "\\server\MemForensics" -Recurse

# Set permissions
icacls "\\server\MemForensics" /grant "DOMAIN\Users:(OI)(CI)(R)"
```

**Step 2: Install Dependencies**
```bash
# On each client with admin privileges
net use z: \\server\MemForensics
z:
pip install -r requirements.txt
python main.py
```

### Linux NFS Setup

```bash
# On NFS server
sudo mkdir -p /export/MemForensics
sudo cp -r MemForensics/* /export/MemForensics/

# In /etc/exports
/export/MemForensics *(ro,sync,no_subtree_check)

# On client
mkdir ~/MemForensics
sudo mount -t nfs server:/export/MemForensics ~/MemForensics
cd ~/MemForensics
pip3 install -r requirements.txt
python3 main.py
```

---

## Configuration Management

### Create Config File

**config.json**
```json
{
  "memory_analysis": {
    "chunk_size": 1048576,
    "entropy_threshold": 7.5,
    "max_strings": 100
  },
  "file_carving": {
    "confidence_threshold": 0.7,
    "file_types": ["jpeg", "png", "mp4"],
    "max_file_size": 1073741824
  },
  "output": {
    "format": "json",
    "include_hashes": true,
    "timestamp": true
  },
  "logging": {
    "level": "INFO",
    "file": "toolkit.log"
  }
}
```

### Load Config in main.py
```python
import json

def load_config(config_path="config.json"):
    with open(config_path, 'r') as f:
        return json.load(f)

config = load_config()
```

---

## Verification & Testing

### Post-Installation Checks

**Windows**
```bash
# Verify Python
python --version

# Verify imports
python -c "from PyQt6.QtWidgets import QApplication; print('PyQt6 OK')"
python -c "import psutil; print('psutil OK')"
python -c "import volatility3; print('volatility3 OK')"

# Check WinPmem (optional)
winpmem_mini_x64.exe --version
```

**Linux**
```bash
# Verify Python
python3 --version

# Verify imports
python3 -c "from PyQt6.QtWidgets import QApplication; print('PyQt6 OK')"
python3 -c "import psutil; print('psutil OK')"
python3 -c "import volatility3; print('volatility3 OK')"

# Check system tools
which volatility3
which yara
```

### Test Functionality

```bash
# Test GUI launch
python main.py

# Test individual modules
python -c "from system_scanner import SystemScanner; print('Scanner OK')"
python -c "from file_carver import FileScarver; print('Carver OK')"
python -c "from memory_dumper import MemoryDumper; print('Dumper OK')"

# Test with sample data (if available)
python file_carver.py --test
```

---

## Troubleshooting Installation

### Issue: PyQt6 Import Error

**Windows**
```bash
# Reinstall PyQt6
pip uninstall PyQt6 -y
pip install PyQt6==6.6.1

# Or use PyQt5
pip install PyQt5
# Edit main.py imports to use PyQt5
```

**Linux**
```bash
# Install system dependencies
sudo apt-get install python3-pyqt6
sudo apt-get install libqt6gui6

# Reinstall
pip3 uninstall PyQt6 -y
pip3 install PyQt6==6.6.1 --no-cache-dir
```

### Issue: Permission Denied

**Windows**
```bash
# Run Command Prompt as Administrator
# Or use:
runas /user:Administrator cmd.exe
```

**Linux**
```bash
# Use sudo for memory operations
sudo python3 main.py

# Or add user to appropriate groups
sudo usermod -aG kvm $USER
sudo usermod -aG disk $USER
```

### Issue: Module Not Found

```bash
# Add to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Or modify main.py
import sys
sys.path.insert(0, '/path/to/MemForensics')
```

### Issue: Out of Memory

```bash
# Reduce chunk size in memory_dumper.py
chunk_size = 1024 * 1024  # 1MB instead of 10MB

# Or use system swap
# Windows: Virtual Memory settings
# Linux: Create swap file
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## Uninstallation

### Windows

```bash
# Remove from Programs
# Control Panel > Programs > Uninstall

# Or via Command Prompt
pip uninstall PyQt6 psutil volatility3 -y

# Remove directory
rmdir /s C:\Path\To\MemForensics
```

### Linux

```bash
# Remove Python packages
pip3 uninstall PyQt6 psutil volatility3 -y

# Remove directory
rm -rf ~/Desktop/X12/MemForensics

# Remove system packages (if installed)
sudo apt-get remove volatility3 yara
```

---

## Update & Maintenance

### Check for Updates

```bash
# Verify current version
python -c "import main; print(main.VERSION)"

# Check dependency versions
pip list

# Update all packages
pip install --upgrade -r requirements.txt
```

### Backup Configuration

```bash
# Backup settings
cp config.json config.json.backup
cp -r ~/.config/MemForensics ~/.config/MemForensics.backup

# Restore if needed
cp config.json.backup config.json
```

---

## Security Considerations

### Installation Security

- [ ] Download from trusted source
- [ ] Verify SHA256 hash of installation files
- [ ] Use HTTPS for all downloads
- [ ] Keep Python and dependencies updated
- [ ] Scan for malware before installation
- [ ] Run in isolated environment if analyzing untrusted files

### Runtime Security

- [ ] Run with minimal required privileges
- [ ] Disable network access if analyzing malware
- [ ] Use virtual machine for malware analysis
- [ ] Enable audit logging
- [ ] Restrict file access permissions
- [ ] Encrypt sensitive output files

---

## Performance Optimization

### Windows Optimization

```batch
# Disable unnecessary services
# Open Services.msc and disable:
# - Windows Update (during analysis)
# - Windows Defender (if not needed)
# - Background Intelligent Transfer Service

# Increase virtual memory
# Settings > System > Advanced > Performance
```

### Linux Optimization

```bash
# Increase file descriptor limits
ulimit -n 65535

# Disable swap (if ample RAM)
sudo swapoff -a

# Enable CPU frequency scaling
sudo powertop --auto-tune

# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups
```

---

## Support & Maintenance

### Regular Maintenance

- Monthly: Update Python and libraries
- Quarterly: Review and update signatures
- Semi-annually: Full system compatibility check
- Annually: Major version upgrade evaluation

### Monitoring

- Log analysis for errors
- Performance profiling
- Memory usage tracking
- Disk space monitoring

### Backup Strategy

```bash
# Daily backup of configuration
cp -r ~/.config/MemForensics /backup/memforensics-$(date +%Y%m%d)/

# Weekly backup of analysis results
find ~/analysis -type f -mtime -7 -exec cp {} /backup/weekly/ \;

# Monthly full system backup
tar -czf /backup/memforensics-full-$(date +%Y%m).tar.gz ~/Desktop/X12/MemForensics
```

---

## Next Steps

1. ✓ Install toolkit (this guide)
2. → Read [QUICKSTART.md](QUICKSTART.md) for first use
3. → Review [README.md](README.md) for full documentation
4. → Study [FEATURES_COMPLETE.md](FEATURES_COMPLETE.md) for all capabilities

---

## Support Contacts

- **Documentation**: See README.md
- **Issues**: Check main.py error messages
- **Guidance**: Review FEATURES_COMPLETE.md examples

---

**Version**: 1.0
**Last Updated**: 2026-02-08
**Compatibility**: Python 3.8+, Windows 7+, Linux 3.0+
