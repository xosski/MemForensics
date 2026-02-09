#!/usr/bin/env python3
"""
Setup script for Advanced Memory Forensic Toolkit
"""

import os
import sys
import subprocess
import platform
from pathlib import Path


class SetupManager:
    """Manage toolkit installation and setup"""

    def __init__(self):
        self.os_type = platform.system()
        self.toolkit_dir = Path(__file__).parent
        self.success = True

    def install_dependencies(self):
        """Install Python dependencies"""
        print("[*] Installing Python dependencies...")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "-r",
                str(self.toolkit_dir / "requirements.txt")
            ])
            print("[+] Python dependencies installed")
        except Exception as e:
            print(f"[-] Failed to install dependencies: {e}")
            self.success = False

    def check_admin_privileges(self):
        """Check for admin/root privileges"""
        print("[*] Checking privileges...")
        if self.os_type == 'Windows':
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    print("[!] Warning: Not running as administrator")
                    print("[!] Memory dumping will require admin privileges")
                else:
                    print("[+] Running with administrator privileges")
            except:
                print("[!] Could not verify admin status")
        else:
            if os.geteuid() == 0:
                print("[+] Running with root privileges")
            else:
                print("[!] Warning: Not running as root")
                print("[!] Memory dumping will require root privileges")

    def setup_windows(self):
        """Windows-specific setup"""
        print("\n[*] Setting up for Windows...")

        # Check for WinPmem
        print("[*] Checking for WinPmem...")
        winpmem_locations = [
            Path("C:/Program Files/WinPmem/winpmem_mini_x64.exe"),
            Path("C:/Program Files (x86)/WinPmem/winpmem_mini_x64.exe"),
            Path.home() / "Downloads" / "winpmem_mini_x64.exe",
        ]

        found_winpmem = False
        for loc in winpmem_locations:
            if loc.exists():
                print(f"[+] Found WinPmem at {loc}")
                found_winpmem = True
                break

        if not found_winpmem:
            print("[!] WinPmem not found (optional)")
            print("[*] Download from: https://github.com/Velocidex/WinPmem")
            print("[*] Place winpmem_mini_x64.exe in Program Files or current directory")

        # Check for volatility3
        print("[*] Checking for Volatility3...")
        try:
            result = subprocess.run(['vol', '--version'], capture_output=True)
            if result.returncode == 0:
                print("[+] Volatility3 found")
        except:
            print("[!] Volatility3 not found (optional)")
            print("[*] Install with: pip install volatility3")

    def setup_linux(self):
        """Linux-specific setup"""
        print("\n[*] Setting up for Linux...")

        # Check for required tools
        tools = ['file', 'strings', 'xxd']
        for tool in tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True)
                if result.returncode == 0:
                    print(f"[+] Found {tool}")
                else:
                    print(f"[!] {tool} not found")
            except:
                print(f"[!] Could not check for {tool}")

        # Check for volatility3
        print("[*] Checking for Volatility3...")
        try:
            result = subprocess.run(['vol', '--version'], capture_output=True)
            if result.returncode == 0:
                print("[+] Volatility3 found")
        except:
            print("[!] Volatility3 not found (optional)")
            print("[*] Install with: sudo apt-get install volatility3")

    def create_shortcuts(self):
        """Create launch shortcuts"""
        print("\n[*] Creating launch shortcuts...")

        if self.os_type == 'Windows':
            # Create .bat file
            bat_content = """@echo off
cd /d "%~dp0"
python main.py
pause
"""
            bat_path = self.toolkit_dir / "run.bat"
            with open(bat_path, 'w') as f:
                f.write(bat_content)
            print(f"[+] Created {bat_path}")

            # Create .vbs for admin privileges
            vbs_content = """Set oShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")
strPath = FSO.GetParentFolderName(WScript.ScriptFullName)
oShell.Run("cmd /c cd /d " & strPath & " && python main.py"), 1, False
"""
            vbs_path = self.toolkit_dir / "run_admin.vbs"
            with open(vbs_path, 'w') as f:
                f.write(vbs_content)
            print(f"[+] Created {vbs_path}")

        else:
            # Create .sh file
            sh_content = """#!/bin/bash
cd "$(dirname "$0")"
python3 main.py
"""
            sh_path = self.toolkit_dir / "run.sh"
            with open(sh_path, 'w') as f:
                f.write(sh_content)
            os.chmod(sh_path, 0o755)
            print(f"[+] Created {sh_path}")

    def verify_installation(self):
        """Verify toolkit installation"""
        print("\n[*] Verifying installation...")

        required_files = [
            'main.py',
            'memory_dumper.py',
            'file_carver.py',
            'unallocated_scanner.py',
            'advanced_scanner.py',
            'requirements.txt',
        ]

        all_present = True
        for file in required_files:
            path = self.toolkit_dir / file
            if path.exists():
                print(f"[+] {file}")
            else:
                print(f"[-] {file} MISSING")
                all_present = False

        return all_present

    def run_setup(self):
        """Run full setup process"""
        print("=" * 60)
        print("Advanced Memory Forensic Toolkit - Setup")
        print("=" * 60)

        # Verify files
        if not self.verify_installation():
            print("\n[-] Some required files are missing!")
            return False

        # Check privileges
        self.check_admin_privileges()

        # Install dependencies
        self.install_dependencies()

        # Platform-specific setup
        if self.os_type == 'Windows':
            self.setup_windows()
        else:
            self.setup_linux()

        # Create shortcuts
        self.create_shortcuts()

        # Final status
        print("\n" + "=" * 60)
        if self.success:
            print("[+] Setup completed successfully!")
            print("\nTo start the toolkit:")
            if self.os_type == 'Windows':
                print("  - Double-click run.bat (normal mode)")
                print("  - Double-click run_admin.vbs (admin mode)")
            else:
                print("  - ./run.sh")
                print("  - sudo python3 main.py (for memory access)")
        else:
            print("[-] Setup completed with errors")
            print("[!] Please check the messages above")

        print("=" * 60)
        return self.success


def main():
    """Main entry point"""
    manager = SetupManager()

    try:
        manager.run_setup()
    except KeyboardInterrupt:
        print("\n\n[!] Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Setup failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
