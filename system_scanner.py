"""
Active system scanner for Windows installations
Scans running system in real-time for malware, rootkits, and artifacts
"""

import os
import sys
import subprocess
import winreg
import ctypes
from pathlib import Path
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from datetime import datetime


class ThreatSeverity(Enum):
    """Threat severity levels"""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class SystemFinding:
    """System scan finding"""
    finding_type: str
    severity: ThreatSeverity
    path: str
    description: str
    details: Dict = None
    hash_md5: str = None
    hash_sha256: str = None


class RegistryScanner:
    """Scan Windows Registry for suspicious entries"""

    # Known malware registry locations
    SUSPICIOUS_REGISTRY_PATHS = {
        'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': 'Auto-start programs',
        'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce': 'Run-once programs',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': 'User auto-start',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce': 'User run-once',
        'HKLM\\System\\CurrentControlSet\\Services': 'System services',
        'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon': 'Logon scripts',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders': 'Shell folders',
        'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders': 'System shell folders',
        'HKLM\\SOFTWARE\\Classes\\*\\Shell\\Open\\command': 'File association handlers',
        'HKLM\\Software\\Microsoft\\Internet Explorer\\Main\\Search': 'Search provider hijacking',
        'HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\Search': 'User search hijacking',
    }

    # Suspicious registry value names
    SUSPICIOUS_VALUE_NAMES = [
        'AppInit_DLLs',
        'LoadAppInit_DLLs',
        'Notify',
        'Shell',
        'Shell Execute Hooks',
        'Image File Execution Options',
        'GlobalFlag',
        'Debugger',
    ]

    def __init__(self):
        self.findings = []

    def scan_registry(self, progress_callback: Optional[Callable] = None) -> List[SystemFinding]:
        """Scan entire registry for suspicious entries"""
        self.findings = []
        
        # Scan auto-start locations
        self._scan_autostart(progress_callback)
        
        # Scan services
        self._scan_services(progress_callback)
        
        # Scan shell extensions
        self._scan_shell_extensions(progress_callback)
        
        # Scan file associations
        self._scan_file_associations(progress_callback)
        
        # Scan browser settings
        self._scan_browser_settings(progress_callback)
        
        return self.findings

    def _scan_autostart(self, progress_callback: Optional[Callable] = None):
        """Scan auto-start registry locations"""
        autostart_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
        ]

        for hkey, path in autostart_paths:
            try:
                with winreg.OpenKey(hkey, path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            
                            # Check for suspicious patterns
                            severity = self._assess_autostart_threat(name, value)
                            if severity != ThreatSeverity.INFO:
                                finding = SystemFinding(
                                    finding_type='Registry Autostart',
                                    severity=severity,
                                    path=f'{hkey}\\{path}\\{name}',
                                    description=f'Autostart entry: {value}',
                                    details={'value': value, 'entry_name': name}
                                )
                                self.findings.append(finding)
                            
                            i += 1
                        except OSError:
                            break
            except Exception as e:
                print(f"Error scanning {path}: {e}")

    def _scan_services(self, progress_callback: Optional[Callable] = None):
        """Scan system services"""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                               r'System\CurrentControlSet\Services') as key:
                i = 0
                while True:
                    try:
                        service_name = winreg.EnumKey(key, i)
                        
                        # Check service details
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                              f'System\\CurrentControlSet\\Services\\{service_name}') as svc_key:
                                try:
                                    image_path, _ = winreg.QueryValueEx(svc_key, 'ImagePath')
                                    start_type, _ = winreg.QueryValueEx(svc_key, 'Start')
                                    
                                    # Check for suspicious characteristics
                                    if self._is_suspicious_service(service_name, image_path, start_type):
                                        severity = ThreatSeverity.MEDIUM if start_type == 2 else ThreatSeverity.LOW
                                        finding = SystemFinding(
                                            finding_type='Suspicious Service',
                                            severity=severity,
                                            path=f'Services\\{service_name}',
                                            description=f'Service: {service_name}',
                                            details={
                                                'image_path': image_path,
                                                'start_type': start_type
                                            }
                                        )
                                        self.findings.append(finding)
                                except:
                                    pass
                        except:
                            pass
                        
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            print(f"Error scanning services: {e}")

    def _scan_shell_extensions(self, progress_callback: Optional[Callable] = None):
        """Scan shell extensions for malware"""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r'Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad') as key:
                i = 0
                while True:
                    try:
                        ext_name, ext_clsid, _ = winreg.EnumValue(key, i)
                        
                        # Check for known malicious extensions
                        if self._is_suspicious_extension(ext_name, ext_clsid):
                            finding = SystemFinding(
                                finding_type='Suspicious Shell Extension',
                                severity=ThreatSeverity.HIGH,
                                path=f'ShellServiceObjectDelayLoad\\{ext_name}',
                                description=f'Shell extension: {ext_name}',
                                details={'clsid': ext_clsid}
                            )
                            self.findings.append(finding)
                        
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            print(f"Error scanning shell extensions: {e}")

    def _scan_file_associations(self, progress_callback: Optional[Callable] = None):
        """Scan file associations for malware"""
        suspicious_extensions = ['.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js']
        
        for ext in suspicious_extensions:
            try:
                with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, 
                                   f'{ext}\\shell\\open\\command') as key:
                    try:
                        command, _ = winreg.QueryValueEx(key, '')
                        
                        if self._is_suspicious_file_handler(command):
                            finding = SystemFinding(
                                finding_type='Suspicious File Association',
                                severity=ThreatSeverity.HIGH,
                                path=f'HKCR\\{ext}\\shell\\open\\command',
                                description=f'File association for {ext}',
                                details={'handler': command}
                            )
                            self.findings.append(finding)
                    except:
                        pass
            except:
                pass

    def _scan_browser_settings(self, progress_callback: Optional[Callable] = None):
        """Scan browser hijacking"""
        browser_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Internet Explorer\SearchScopes'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Internet Explorer\Main'),
        ]

        for hkey, path in browser_paths:
            try:
                with winreg.OpenKey(hkey, path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            
                            if 'home' in name.lower() or 'search' in name.lower():
                                if self._is_suspicious_url(value):
                                    finding = SystemFinding(
                                        finding_type='Browser Hijacking',
                                        severity=ThreatSeverity.MEDIUM,
                                        path=f'{path}\\{name}',
                                        description='Suspicious browser setting',
                                        details={'value': value}
                                    )
                                    self.findings.append(finding)
                            
                            i += 1
                        except OSError:
                            break
            except:
                pass

    def _assess_autostart_threat(self, name: str, value: str) -> ThreatSeverity:
        """Assess threat level of autostart entry"""
        suspicious_patterns = [
            'svchost',  # Often spoofed
            'rundll32',  # Commonly abused
            'regsvcs',  # Living off the land
            'temp',  # Suspicious location
            'appdata',  # Suspicious location
            '.zip',  # Unusual for executable
            'cmd /c',  # Command execution
            'powershell',  # Living off the land
        ]

        for pattern in suspicious_patterns:
            if pattern.lower() in value.lower():
                return ThreatSeverity.MEDIUM

        return ThreatSeverity.INFO

    def _is_suspicious_service(self, name: str, image_path: str, start_type: int) -> bool:
        """Check if service is suspicious"""
        suspicious_service_names = [
            'svchost',
            'rundll32',
            'cmd',
            'powershell',
        ]

        for suspicious in suspicious_service_names:
            if suspicious.lower() in name.lower():
                return True

        # Check path legitimacy
        if image_path:
            legit_paths = [
                'c:\\windows',
                'c:\\program files',
                'c:\\progra~1',
            ]
            if not any(path in image_path.lower() for path in legit_paths):
                return True

        return False

    def _is_suspicious_extension(self, name: str, clsid: str) -> bool:
        """Check if shell extension is suspicious"""
        # This would check against known malicious extensions
        return False

    def _is_suspicious_file_handler(self, handler: str) -> bool:
        """Check if file handler is suspicious"""
        if 'powershell' in handler.lower() or 'cmd' in handler.lower():
            return True
        return False

    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL is suspicious"""
        suspicious_domains = [
            'search.saferbrowsing',
            'delta-search',
            'search.conduit',
        ]

        for domain in suspicious_domains:
            if domain in url.lower():
                return True

        return False


class FileSystemScanner:
    """Scan active Windows file system"""

    def __init__(self):
        self.findings = []
        self.critical_paths = [
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\ProgramData',
            os.path.expanduser('~\\AppData\\Local'),
            os.path.expanduser('~\\AppData\\Roaming'),
        ]

    def scan_file_system(self, progress_callback: Optional[Callable] = None) -> List[SystemFinding]:
        """Scan file system for malware"""
        self.findings = []

        for path in self.critical_paths:
            if os.path.exists(path):
                self._scan_directory(path, progress_callback)

        return self.findings

    def _scan_directory(self, path: str, progress_callback: Optional[Callable] = None):
        """Recursively scan directory"""
        try:
            for root, dirs, files in os.walk(path, topdown=True):
                # Limit depth
                if root.count(os.sep) - path.count(os.sep) > 3:
                    dirs.clear()
                    continue

                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Check file
                    if self._is_suspicious_file(file_path):
                        finding = SystemFinding(
                            finding_type='Suspicious File',
                            severity=ThreatSeverity.HIGH,
                            path=file_path,
                            description=f'Suspicious file detected',
                            details={'file_name': file},
                            hash_md5=self._hash_file(file_path, 'md5'),
                        )
                        self.findings.append(finding)

                    if progress_callback:
                        progress_callback(0, f'Scanning {file_path}')

        except Exception as e:
            print(f"Error scanning {path}: {e}")

    def _is_suspicious_file(self, file_path: str) -> bool:
        """Check if file is suspicious"""
        suspicious_extensions = ['.exe', '.dll', '.sys', '.scr', '.vbs', '.js']
        suspicious_names = ['svchost', 'rundll32', 'malware', 'trojan']

        try:
            file_name = os.path.basename(file_path).lower()

            # Check extension
            if any(file_name.endswith(ext) for ext in suspicious_extensions):
                # Check if in temp directory
                if 'temp' in file_path.lower() or 'appdata' in file_path.lower():
                    return True

            # Check file name
            for suspicious in suspicious_names:
                if suspicious in file_name:
                    return True

            # Check file size (suspicious if 0 or extremely large)
            size = os.path.getsize(file_path)
            if size == 0 or size > 100 * 1024 * 1024:  # 100MB
                return False  # Not necessarily suspicious

        except Exception as e:
            print(f"Error checking {file_path}: {e}")

        return False

    def _hash_file(self, file_path: str, hash_type: str = 'md5') -> Optional[str]:
        """Calculate file hash"""
        try:
            if hash_type == 'md5':
                hasher = hashlib.md5()
            else:
                hasher = hashlib.sha256()

            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)

            return hasher.hexdigest()
        except:
            return None


class ProcessMemoryScanner:
    """Scan active process memory"""

    def __init__(self):
        self.findings = []

    def scan_processes(self, progress_callback: Optional[Callable] = None) -> List[SystemFinding]:
        """Scan all running processes"""
        self.findings = []

        try:
            import psutil
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd']):
                try:
                    if proc.info['name']:
                        # Check for suspicious processes
                        if self._is_suspicious_process(proc.info):
                            severity = ThreatSeverity.MEDIUM
                            finding = SystemFinding(
                                finding_type='Suspicious Process',
                                severity=severity,
                                path=f"PID: {proc.info['pid']}",
                                description=f"Process: {proc.info['name']}",
                                details={
                                    'pid': proc.info['pid'],
                                    'name': proc.info['name'],
                                    'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else 'N/A'
                                }
                            )
                            self.findings.append(finding)

                        if progress_callback:
                            progress_callback(0, f'Scanning process: {proc.info["name"]}')

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        except ImportError:
            print("psutil not available")

        return self.findings

    def _is_suspicious_process(self, proc_info: Dict) -> bool:
        """Check if process is suspicious"""
        suspicious_names = [
            'svchost.exe',  # Check for spoofing
            'rundll32',
            'regsvcs',
            'regasm',
            'cscript',
            'wscript',
        ]

        proc_name = proc_info.get('name', '').lower()

        # Check for exact suspicious matches with unusual paths
        for suspicious in suspicious_names:
            if suspicious.lower() in proc_name:
                # If it's svchost but path is not system32, it's suspicious
                if suspicious == 'svchost.exe':
                    if proc_info.get('cwd') and 'system32' not in proc_info['cwd'].lower():
                        return True
                else:
                    return True

        # Check for PowerShell with suspicious arguments
        if 'powershell' in proc_name:
            cmdline = ' '.join(proc_info.get('cmdline', [])).lower()
            if any(x in cmdline for x in ['-encodedcommand', 'invoke-webrequest', 'iwr']):
                return True

        return False


class SystemScanner:
    """Master system scanner"""

    def __init__(self):
        self.registry_scanner = RegistryScanner()
        self.filesystem_scanner = FileSystemScanner()
        self.process_scanner = ProcessMemoryScanner()
        self.all_findings = []

    def full_system_scan(self, scan_registry: bool = True, scan_filesystem: bool = True,
                        scan_processes: bool = True,
                        progress_callback: Optional[Callable] = None) -> List[SystemFinding]:
        """Run full system scan"""
        self.all_findings = []

        if scan_registry:
            if progress_callback:
                progress_callback(0, "Scanning Registry...")
            findings = self.registry_scanner.scan_registry(progress_callback)
            self.all_findings.extend(findings)

        if scan_processes:
            if progress_callback:
                progress_callback(25, "Scanning Processes...")
            findings = self.process_scanner.scan_processes(progress_callback)
            self.all_findings.extend(findings)

        if scan_filesystem:
            if progress_callback:
                progress_callback(50, "Scanning File System...")
            findings = self.filesystem_scanner.scan_file_system(progress_callback)
            self.all_findings.extend(findings)

        if progress_callback:
            progress_callback(100, f"Scan complete: {len(self.all_findings)} findings")

        return self.all_findings

    def get_severity_summary(self) -> Dict:
        """Get summary of findings by severity"""
        summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0,
        }

        for finding in self.all_findings:
            summary[finding.severity.name] += 1

        return summary

    def export_findings(self, output_path: str, format_type: str = 'json'):
        """Export findings to file"""
        if format_type == 'json':
            data = {
                'scan_time': datetime.now().isoformat(),
                'summary': self.get_severity_summary(),
                'findings': [
                    {
                        'type': f.finding_type,
                        'severity': f.severity.name,
                        'path': f.path,
                        'description': f.description,
                        'details': f.details,
                        'hash_md5': f.hash_md5,
                    }
                    for f in self.all_findings
                ]
            }

            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)

        elif format_type == 'csv':
            import csv
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Type', 'Severity', 'Path', 'Description'])
                for finding in self.all_findings:
                    writer.writerow([
                        finding.finding_type,
                        finding.severity.name,
                        finding.path,
                        finding.description
                    ])
