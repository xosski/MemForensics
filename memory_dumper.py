"""
Memory dumping module for active memory acquisition
Supports Windows (WinPmem) and Linux (dd, /dev/mem)
"""

import subprocess
import os
import platform
import ctypes
import struct
from typing import Optional, Callable, List, Dict
from pathlib import Path
import tempfile


class MemoryDumper:
    """Dump active system memory"""

    def __init__(self):
        self.os_type = platform.system()
        self.is_admin = self._check_admin()
        self.dumper_path = None

    def _check_admin(self) -> bool:
        """Check if running with admin privileges"""
        if self.os_type == 'Windows':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            return os.geteuid() == 0

    def _find_winpmem(self) -> Optional[str]:
        """Locate WinPmem driver"""
        possible_paths = [
            'C:\\Program Files\\WinPmem\\winpmem_mini_x64.exe',
            'C:\\Program Files (x86)\\WinPmem\\winpmem_mini_x64.exe',
            os.path.expanduser('~\\Downloads\\winpmem_mini_x64.exe'),
            '.\\winpmem_mini_x64.exe',
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        return None

    def dump_memory_windows(self, output_file: str, progress_callback: Optional[Callable] = None) -> bool:
        """Dump memory on Windows using WinPmem"""
        if not self.is_admin:
            raise PermissionError("Administrator privileges required for memory dump")

        # Try WinPmem first
        winpmem_path = self._find_winpmem()

        if winpmem_path:
            return self._dump_with_winpmem(winpmem_path, output_file, progress_callback)

        # Fallback: Use Win32 API through raw disk access
        return self._dump_with_win32(output_file, progress_callback)

    def _dump_with_winpmem(self, winpmem_path: str, output_file: str, 
                           progress_callback: Optional[Callable] = None) -> bool:
        """Use WinPmem to dump memory"""
        try:
            cmd = [winpmem_path, '-o', output_file]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            total_written = 0
            for line in process.stdout:
                if progress_callback and 'Progress' in line:
                    # Extract progress percentage
                    try:
                        progress = int(''.join(filter(str.isdigit, line)))
                        progress_callback(progress, line.strip())
                    except:
                        pass

            process.wait()
            return process.returncode == 0
        except Exception as e:
            print(f"WinPmem error: {e}")
            return False

    def _dump_with_win32(self, output_file: str, progress_callback: Optional[Callable] = None) -> bool:
        """Dump memory using Win32 API (backup method)"""
        try:
            from ctypes import windll, wintypes, byref, c_ulong

            # Get memory info
            kernel32 = windll.kernel32
            GetSystemInfo = kernel32.GetSystemInfo
            ReadProcessMemory = kernel32.ReadProcessMemory

            class SYSTEM_INFO(ctypes.Structure):
                _fields_ = [("wProcessorArchitecture", wintypes.WORD),
                           ("wReserved", wintypes.WORD),
                           ("dwPageSize", wintypes.DWORD),
                           ("lpMinimumApplicationAddress", wintypes.LPVOID),
                           ("lpMaximumApplicationAddress", wintypes.LPVOID),
                           ("dwActiveProcessorMask", wintypes.DWORD),
                           ("dwNumberOfProcessors", wintypes.DWORD),
                           ("dwProcessorType", wintypes.DWORD),
                           ("dwAllocationGranularity", wintypes.DWORD),
                           ("wProcessorLevel", wintypes.WORD),
                           ("wProcessorRevision", wintypes.WORD)]

            sys_info = SYSTEM_INFO()
            GetSystemInfo(byref(sys_info))

            with open(output_file, 'wb') as f:
                current_addr = 0
                page_size = sys_info.dwPageSize
                max_addr = int(sys_info.lpMaximumApplicationAddress)

                while current_addr < max_addr:
                    try:
                        buffer = ctypes.create_string_buffer(page_size)
                        bytes_read = c_ulong()

                        result = ReadProcessMemory(
                            -1,  # Current process
                            current_addr,
                            buffer,
                            page_size,
                            byref(bytes_read)
                        )

                        if result and bytes_read.value > 0:
                            f.write(buffer.raw[:bytes_read.value])

                            if progress_callback:
                                progress = int((current_addr / max_addr) * 100)
                                progress_callback(progress, f"Dumped {current_addr / (1024**3):.2f} GB")

                    except Exception as e:
                        print(f"Read error at {hex(current_addr)}: {e}")

                    current_addr += page_size

            return True
        except Exception as e:
            print(f"Win32 dump error: {e}")
            return False

    def dump_memory_linux(self, output_file: str, progress_callback: Optional[Callable] = None) -> bool:
        """Dump memory on Linux"""
        if not self.is_admin:
            raise PermissionError("Root privileges required for memory dump")

        # Try /proc/kcore first (preferred)
        if os.path.exists('/proc/kcore'):
            return self._dump_kcore(output_file, progress_callback)

        # Fallback: /dev/mem
        if os.path.exists('/dev/mem'):
            return self._dump_dev_mem(output_file, progress_callback)

        # Last resort: dd from physical memory
        return self._dump_with_dd(output_file, progress_callback)

    def _dump_kcore(self, output_file: str, progress_callback: Optional[Callable] = None) -> bool:
        """Dump /proc/kcore"""
        try:
            file_size = os.path.getsize('/proc/kcore')

            with open('/proc/kcore', 'rb') as src:
                with open(output_file, 'wb') as dst:
                    chunk_size = 4 * 1024 * 1024  # 4MB chunks
                    bytes_read = 0

                    while True:
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break

                        dst.write(chunk)
                        bytes_read += len(chunk)

                        if progress_callback:
                            progress = int((bytes_read / file_size) * 100)
                            progress_callback(progress, f"Dumped {bytes_read / (1024**3):.2f} GB")

            return True
        except Exception as e:
            print(f"kcore dump error: {e}")
            return False

    def _dump_dev_mem(self, output_file: str, progress_callback: Optional[Callable] = None) -> bool:
        """Dump /dev/mem"""
        try:
            # Get system memory size from /proc/meminfo
            total_mem = 0
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        total_mem = int(line.split()[1]) * 1024
                        break

            with open('/dev/mem', 'rb') as src:
                with open(output_file, 'wb') as dst:
                    chunk_size = 4 * 1024 * 1024  # 4MB chunks
                    bytes_read = 0

                    while bytes_read < total_mem:
                        chunk = src.read(min(chunk_size, total_mem - bytes_read))
                        if not chunk:
                            break

                        dst.write(chunk)
                        bytes_read += len(chunk)

                        if progress_callback:
                            progress = int((bytes_read / total_mem) * 100) if total_mem else 0
                            progress_callback(progress, f"Dumped {bytes_read / (1024**3):.2f} GB")

            return True
        except Exception as e:
            print(f"dev/mem dump error: {e}")
            return False

    def _dump_with_dd(self, output_file: str, progress_callback: Optional[Callable] = None) -> bool:
        """Dump using dd command"""
        try:
            # Get total RAM
            result = subprocess.run(['free', '-b'], capture_output=True, text=True)
            total_mem = int(result.stdout.split('\n')[1].split()[1])

            cmd = f'dd if=/dev/mem of={output_file} bs=4M'
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            for line in process.stderr:
                if progress_callback and 'bytes' in line:
                    try:
                        bytes_read = int(line.split()[0])
                        progress = int((bytes_read / total_mem) * 100)
                        progress_callback(progress, line.strip())
                    except:
                        pass

            process.wait()
            return process.returncode == 0
        except Exception as e:
            print(f"dd dump error: {e}")
            return False

    def dump_process_memory(self, pid: int, output_file: str, 
                           progress_callback: Optional[Callable] = None) -> bool:
        """Dump specific process memory"""
        try:
            if self.os_type == 'Windows':
                return self._dump_process_windows(pid, output_file, progress_callback)
            else:
                return self._dump_process_linux(pid, output_file, progress_callback)
        except Exception as e:
            print(f"Process dump error: {e}")
            return False

    def _dump_process_windows(self, pid: int, output_file: str, 
                             progress_callback: Optional[Callable] = None) -> bool:
        """Dump Windows process memory"""
        try:
            from ctypes import windll, wintypes, byref, c_ulong

            kernel32 = windll.kernel32
            OpenProcess = kernel32.OpenProcess
            ReadProcessMemory = kernel32.ReadProcessMemory
            CloseHandle = kernel32.CloseHandle

            PROCESS_VM_READ = 0x0010

            h_process = OpenProcess(PROCESS_VM_READ, False, pid)
            if not h_process:
                return False

            with open(output_file, 'wb') as f:
                current_addr = 0
                page_size = 4096

                while current_addr < 0x7FFFFFFF:
                    try:
                        buffer = ctypes.create_string_buffer(page_size)
                        bytes_read = c_ulong()

                        ReadProcessMemory(
                            h_process,
                            current_addr,
                            buffer,
                            page_size,
                            byref(bytes_read)
                        )

                        if bytes_read.value > 0:
                            f.write(buffer.raw[:bytes_read.value])

                            if progress_callback:
                                progress = int((current_addr / 0x7FFFFFFF) * 100)
                                progress_callback(progress, f"Dumped {current_addr / (1024**3):.2f} GB")

                    except:
                        pass

                    current_addr += page_size

            CloseHandle(h_process)
            return True
        except Exception as e:
            print(f"Windows process dump error: {e}")
            return False

    def _dump_process_linux(self, pid: int, output_file: str, 
                           progress_callback: Optional[Callable] = None) -> bool:
        """Dump Linux process memory"""
        try:
            maps_file = f'/proc/{pid}/maps'
            mem_file = f'/proc/{pid}/mem'

            if not os.path.exists(maps_file) or not os.path.exists(mem_file):
                return False

            regions = self._parse_proc_maps(maps_file)

            with open(mem_file, 'rb') as src:
                with open(output_file, 'wb') as dst:
                    for i, (start, end, perms) in enumerate(regions):
                        if 'r' not in perms:
                            continue

                        src.seek(start)
                        size = end - start

                        try:
                            data = src.read(size)
                            dst.write(data)

                            if progress_callback:
                                progress = int((i / len(regions)) * 100)
                                progress_callback(progress, f"Dumped region {i}/{len(regions)}")
                        except:
                            pass

            return True
        except Exception as e:
            print(f"Linux process dump error: {e}")
            return False

    def _parse_proc_maps(self, maps_file: str) -> List[tuple]:
        """Parse /proc/[pid]/maps"""
        regions = []
        try:
            with open(maps_file, 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 1:
                        addr_range = parts[0].split('-')
                        if len(addr_range) == 2:
                            start = int(addr_range[0], 16)
                            end = int(addr_range[1], 16)
                            perms = parts[1] if len(parts) > 1 else ''
                            regions.append((start, end, perms))
        except:
            pass

        return regions

    def get_memory_info(self) -> Dict:
        """Get system memory information"""
        import psutil

        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()

        return {
            'total': vm.total,
            'available': vm.available,
            'percent': vm.percent,
            'used': vm.used,
            'free': vm.free,
            'swap_total': swap.total,
            'swap_used': swap.used,
            'swap_free': swap.free,
        }
