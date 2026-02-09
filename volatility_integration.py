"""
Volatility 3 integration for advanced memory forensics
"""

import subprocess
import json
import re
from typing import List, Dict, Optional
from pathlib import Path
import platform


class VolatilityWrapper:
    """Wrapper for Volatility 3 framework"""

    def __init__(self):
        self.volatility_path = self._find_volatility()
        self.os_type = platform.system()

    def _find_volatility(self) -> Optional[str]:
        """Find volatility3 installation"""
        try:
            result = subprocess.run(
                ['vol', '--version'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return 'vol'
        except:
            pass

        try:
            result = subprocess.run(
                ['python3', '-m', 'volatility3', '--version'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return 'python3'
        except:
            pass

        return None

    def is_available(self) -> bool:
        """Check if Volatility is available"""
        return self.volatility_path is not None

    def list_plugins(self, dump_path: str) -> List[str]:
        """List available plugins for dump"""
        if not self.is_available():
            return []

        try:
            cmd = self._build_command(dump_path, 'windows.info' if self.os_type == 'Windows' else 'linux.info')
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            # Parse output for available plugins
            plugins = re.findall(r'Plugin: (\w+)', result.stdout)
            return plugins
        except:
            return []

    def _build_command(self, dump_path: str, plugin: str) -> List[str]:
        """Build volatility command"""
        if self.volatility_path == 'vol':
            return ['vol', '-f', dump_path, plugin]
        else:
            return ['python3', '-m', 'volatility3', '-f', dump_path, plugin]

    def run_pslist(self, dump_path: str) -> List[Dict]:
        """Get process list"""
        if not self.is_available():
            return []

        try:
            plugin = 'windows.pslist.PsList' if self.os_type == 'Windows' else 'linux.pslist.PsList'
            cmd = self._build_command(dump_path, plugin)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            processes = self._parse_process_list(result.stdout)
            return processes
        except Exception as e:
            print(f"Error running pslist: {e}")
            return []

    def _parse_process_list(self, output: str) -> List[Dict]:
        """Parse process list output"""
        processes = []
        lines = output.split('\n')

        for line in lines:
            if line.strip() and not line.startswith('PID'):
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 2:
                    try:
                        processes.append({
                            'pid': int(parts[0]),
                            'name': parts[1] if len(parts) > 1 else 'Unknown',
                            'ppid': int(parts[2]) if len(parts) > 2 else 0,
                        })
                    except (ValueError, IndexError):
                        pass

        return processes

    def run_malfind(self, dump_path: str) -> List[Dict]:
        """Find injected code"""
        if not self.is_available():
            return []

        try:
            plugin = 'windows.malfind.Malfind' if self.os_type == 'Windows' else 'linux.malfind.Malfind'
            cmd = self._build_command(dump_path, plugin)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            detections = self._parse_malfind_output(result.stdout)
            return detections
        except Exception as e:
            print(f"Error running malfind: {e}")
            return []

    def _parse_malfind_output(self, output: str) -> List[Dict]:
        """Parse malfind output"""
        detections = []
        blocks = output.split('\n\n')

        for block in blocks:
            if 'PID' in block and 'Address' in block:
                try:
                    lines = block.split('\n')
                    for line in lines:
                        if 'PID:' in line:
                            pid = int(re.search(r'PID:\s*(\d+)', line).group(1))
                        if 'Address:' in line:
                            addr = re.search(r'Address:\s*(0x[\da-f]+)', line).group(1)
                        if 'Size:' in line:
                            size = int(re.search(r'Size:\s*(\d+)', line).group(1))

                    detections.append({
                        'pid': pid,
                        'address': addr,
                        'size': size,
                        'type': 'Injected Code'
                    })
                except:
                    pass

        return detections

    def run_handles(self, dump_path: str, pid: int = None) -> List[Dict]:
        """Get open handles"""
        if not self.is_available():
            return []

        try:
            plugin = 'windows.handles.Handles' if self.os_type == 'Windows' else 'linux.files.Files'
            cmd = self._build_command(dump_path, plugin)

            if pid:
                cmd.extend(['--pid', str(pid)])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            handles = self._parse_handles_output(result.stdout)
            return handles
        except Exception as e:
            print(f"Error running handles: {e}")
            return []

    def _parse_handles_output(self, output: str) -> List[Dict]:
        """Parse handles output"""
        handles = []
        lines = output.split('\n')

        for line in lines[1:]:  # Skip header
            if line.strip():
                parts = re.split(r'\s+', line.strip(), maxsplit=3)
                if len(parts) >= 3:
                    handles.append({
                        'type': parts[0],
                        'handle': parts[1],
                        'name': parts[3] if len(parts) > 3 else ''
                    })

        return handles

    def run_dlllist(self, dump_path: str, pid: int = None) -> List[Dict]:
        """Get loaded DLLs"""
        if not self.is_available():
            return []

        try:
            plugin = 'windows.dlllist.DllList' if self.os_type == 'Windows' else 'linux.library.Libraries'
            cmd = self._build_command(dump_path, plugin)

            if pid:
                cmd.extend(['--pid', str(pid)])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            dlls = self._parse_dlllist_output(result.stdout)
            return dlls
        except Exception as e:
            print(f"Error running dlllist: {e}")
            return []

    def _parse_dlllist_output(self, output: str) -> List[Dict]:
        """Parse DLL list output"""
        dlls = []
        lines = output.split('\n')

        for line in lines:
            if '.dll' in line.lower() or '.so' in line.lower():
                parts = re.split(r'\s+', line.strip())
                if parts:
                    dlls.append({
                        'path': parts[-1] if parts else '',
                        'base': parts[0] if len(parts) > 0 else '',
                        'size': parts[1] if len(parts) > 1 else ''
                    })

        return dlls

    def run_netscan(self, dump_path: str) -> List[Dict]:
        """Get network connections"""
        if not self.is_available():
            return []

        try:
            plugin = 'windows.netscan.NetScan' if self.os_type == 'Windows' else 'linux.netscan.NetScan'
            cmd = self._build_command(dump_path, plugin)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            connections = self._parse_netscan_output(result.stdout)
            return connections
        except Exception as e:
            print(f"Error running netscan: {e}")
            return []

    def _parse_netscan_output(self, output: str) -> List[Dict]:
        """Parse network scan output"""
        connections = []
        lines = output.split('\n')

        for line in lines:
            if 'ESTABLISHED' in line or 'LISTENING' in line:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 4:
                    connections.append({
                        'protocol': parts[0],
                        'local': parts[1],
                        'remote': parts[2],
                        'state': parts[3]
                    })

        return connections

    def dump_memory_region(self, dump_path: str, pid: int, start: int, end: int, 
                          output_file: str) -> bool:
        """Dump a memory region"""
        if not self.is_available():
            return False

        try:
            plugin = 'windows.memmap.Memmap' if self.os_type == 'Windows' else 'linux.memmap.Memmap'
            cmd = self._build_command(dump_path, plugin)
            cmd.extend(['--pid', str(pid), '--output-file', output_file])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.returncode == 0
        except Exception as e:
            print(f"Error dumping memory: {e}")
            return False
