"""
Advanced Shellcode Detection Module
Detects shellcode patterns, analyzes characteristics, and identifies exploit types
"""

import re
import hashlib
import struct
from typing import List, Dict, Tuple, Optional
from enum import Enum
from collections import Counter


class ShellcodeType(Enum):
    """Shellcode family classification"""
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    EXEC_COMMAND = "exec_command"
    DOWNLOADER = "downloader"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CODE_CAVE = "code_cave"
    UNKNOWN = "unknown"


class Architecture(Enum):
    """Target architecture for shellcode"""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    UNKNOWN = "unknown"


class ShellcodeDetector:
    """Comprehensive shellcode detection and analysis"""

    def __init__(self):
        self.signatures = self._load_shellcode_signatures()
        self.patterns = self._load_detection_patterns()
        self.known_payloads = self._load_known_payloads()

    def _load_shellcode_signatures(self) -> Dict[str, List[bytes]]:
        """Load known shellcode signatures"""
        return {
            'x86_syscall': [
                b'\xcd\x80',  # int 0x80 (Linux syscall)
                b'\x0f\x05',  # syscall (modern x64)
                b'\x65\xff\x15\x10\x00\x00\x00',  # sysenter
            ],
            'x64_syscall': [
                b'\x0f\x05',  # syscall
                b'\x0f\x34',  # sysenter
            ],
            'stack_pivot': [
                b'\x5c\xc3',  # pop rsp; ret
                b'\x5d\xc3',  # pop rbp; ret
                b'\x5f\xc3',  # pop rdi; ret
            ],
            'nop_sled': [
                b'\x90' * 8,   # 8+ NOPs (0x90)
                b'\x66\x90' * 4,  # 2-byte NOPs
            ],
            'jmp_table': [
                b'\xff\x25',  # jmp qword ptr [rip+...]
                b'\xff\x64\x24',  # jmp qword ptr [rsp+...]
            ],
            'socket_creation': [
                b'socket',
                b'WSASocket',
                b'connect',
                b'bind',
            ],
            'exec_functions': [
                b'execve',
                b'CreateProcessA',
                b'CreateProcessW',
                b'WinExec',
                b'ShellExecute',
            ],
            'network_api': [
                b'inet_aton',
                b'inet_addr',
                b'htons',
                b'ntohs',
                b'getaddrinfo',
            ],
        }

    def _load_detection_patterns(self) -> Dict[str, tuple]:
        """Load regex/byte patterns for heuristic detection"""
        return {
            'x86_function_prologue': (
                b'\x55\x89\xe5',  # push ebp; mov ebp, esp
                "x86 function prologue"
            ),
            'x64_function_prologue': (
                b'\x48\x89\xe5',  # mov rbp, rsp
                "x64 function prologue"
            ),
            'stack_adjustment': (
                b'\x81\xec',  # sub esp, imm32
                "Stack allocation (sub esp)"
            ),
            'indirect_call': (
                b'\xff\x15',  # call qword ptr [rip+...]
                "Indirect function call"
            ),
            'return_instruction': (
                b'\xc3',  # ret
                "Return instruction"
            ),
            'conditional_jump': (
                b'\x0f[\x80-\x8f]',  # jcc near
                "Conditional jump"
            ),
        }

    def _load_known_payloads(self) -> Dict[str, Dict]:
        """Load signatures for known shellcode families"""
        return {
            'meterpreter': {
                'signatures': [
                    b'Meterpreter',
                    b'ReflectiveDllInjection',
                    b'msvcrt',
                ],
                'threat_level': 'CRITICAL',
                'description': 'Metasploit Meterpreter payload'
            },
            'reverse_shell_linux': {
                'signatures': [
                    b'/bin/sh',
                    b'/bin/bash',
                ],
                'threat_level': 'HIGH',
                'description': 'Linux reverse shell'
            },
            'mimikatz': {
                'signatures': [
                    b'mimikatz',
                    b'goldenpac',
                    b'msvc',
                ],
                'threat_level': 'CRITICAL',
                'description': 'Credential dumping tool'
            },
            'powershell_download': {
                'signatures': [
                    b'powershell',
                    b'DownloadString',
                    b'IEX',
                ],
                'threat_level': 'HIGH',
                'description': 'PowerShell code execution'
            },
        }

    def detect_shellcode(self, data: bytes) -> List[Dict]:
        """Comprehensive shellcode detection"""
        findings = []

        # Check for shellcode signatures
        sig_matches = self._scan_signatures(data)
        findings.extend(sig_matches)

        # Heuristic analysis
        heuristic_matches = self._heuristic_analysis(data)
        findings.extend(heuristic_matches)

        # Known payload detection
        payload_matches = self._detect_known_payloads(data)
        findings.extend(payload_matches)

        return findings

    def _scan_signatures(self, data: bytes) -> List[Dict]:
        """Scan for known shellcode signatures"""
        matches = []
        for category, sigs in self.signatures.items():
            for sig in sigs:
                offset = 0
                while True:
                    offset = data.find(sig, offset)
                    if offset == -1:
                        break

                    matches.append({
                        'type': 'signature_match',
                        'category': category,
                        'offset': offset,
                        'size': len(sig),
                        'signature': sig.hex(),
                        'threat_level': self._get_threat_level(category),
                        'description': f'Found {category} signature',
                    })
                    offset += 1

        return matches

    def _heuristic_analysis(self, data: bytes) -> List[Dict]:
        """Perform heuristic shellcode analysis"""
        matches = []

        for pattern_name, (pattern, description) in self.patterns.items():
            if isinstance(pattern, bytes):
                offset = 0
                while True:
                    offset = data.find(pattern, offset)
                    if offset == -1:
                        break

                    matches.append({
                        'type': 'heuristic_pattern',
                        'pattern': pattern_name,
                        'offset': offset,
                        'size': len(pattern),
                        'description': description,
                        'threat_level': 'MEDIUM',
                    })
                    offset += 1

        # Detect NOP sleds
        nop_sleds = self._detect_nop_sleds(data)
        matches.extend(nop_sleds)

        # Detect entropy anomalies
        high_entropy = self._detect_high_entropy_regions(data)
        matches.extend(high_entropy)

        return matches

    def _detect_nop_sleds(self, data: bytes, min_length: int = 8) -> List[Dict]:
        """Detect NOP sled patterns (padding before shellcode)"""
        matches = []
        nop_patterns = [
            (b'\x90', 'single-byte NOP (0x90)'),
            (b'\x66\x90', 'two-byte NOP (0x6690)'),
            (b'\x0f\x1f\x00', 'three-byte NOP'),
        ]

        for nop_bytes, description in nop_patterns:
            offset = 0
            while True:
                offset = data.find(nop_bytes, offset)
                if offset == -1:
                    break

                # Count consecutive NOPs
                count = 0
                pos = offset
                while pos < len(data) - len(nop_bytes) + 1:
                    if data[pos:pos+len(nop_bytes)] == nop_bytes:
                        count += len(nop_bytes)
                        pos += len(nop_bytes)
                    else:
                        break

                if count >= min_length:
                    matches.append({
                        'type': 'nop_sled',
                        'offset': offset,
                        'size': count,
                        'description': f'NOP sled ({description}): {count} bytes',
                        'threat_level': 'HIGH',
                    })
                    offset = pos
                else:
                    offset += len(nop_bytes)

        return matches

    def _detect_high_entropy_regions(self, data: bytes, window_size: int = 256) -> List[Dict]:
        """Detect high-entropy regions (potential encrypted shellcode)"""
        matches = []
        entropy_threshold = 7.0

        for i in range(0, len(data) - window_size, window_size // 2):
            chunk = data[i:i+window_size]
            entropy = self._calculate_entropy(chunk)

            if entropy > entropy_threshold:
                matches.append({
                    'type': 'high_entropy_region',
                    'offset': i,
                    'size': window_size,
                    'entropy': round(entropy, 2),
                    'description': f'High-entropy region (potential encrypted shellcode)',
                    'threat_level': 'MEDIUM',
                })

        return matches

    def _detect_known_payloads(self, data: bytes) -> List[Dict]:
        """Detect known malware payloads"""
        matches = []

        for payload_name, payload_info in self.known_payloads.items():
            for sig in payload_info['signatures']:
                if sig in data:
                    offset = data.find(sig)
                    matches.append({
                        'type': 'known_payload',
                        'payload': payload_name,
                        'offset': offset,
                        'signature': sig.hex(),
                        'threat_level': payload_info['threat_level'],
                        'description': payload_info['description'],
                    })

        return matches

    def analyze_shellcode_region(self, data: bytes, base_addr: int = 0) -> Dict:
        """Detailed analysis of suspected shellcode region"""
        analysis = {
            'base_address': hex(base_addr) if isinstance(base_addr, int) else base_addr,
            'size': len(data),
            'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'entropy': round(self._calculate_entropy(data), 2),
            'architecture': self._detect_architecture(data).value,
            'detections': self.detect_shellcode(data),
            'suspicious': False,
        }

        # Mark as suspicious if detections found
        if analysis['detections']:
            analysis['suspicious'] = True

        return analysis

    def _detect_architecture(self, data: bytes) -> Architecture:
        """Attempt to detect target architecture"""
        x86_indicators = 0
        x64_indicators = 0
        arm_indicators = 0

        # x86/x64 indicators
        x86_opcodes = [b'\xcd\x80', b'\xff\x15', b'\x55\x89\xe5']
        x64_opcodes = [b'\x0f\x05', b'\x48\x89\xe5', b'\x48\x8d']

        for opcode in x86_opcodes:
            if opcode in data:
                x86_indicators += 1

        for opcode in x64_opcodes:
            if opcode in data:
                x64_indicators += 1

        if x64_indicators > x86_indicators:
            return Architecture.X64
        elif x86_indicators > 0:
            return Architecture.X86
        elif b'\xed' in data or b'\xee' in data:  # ARM-like patterns
            return Architecture.ARM

        return Architecture.UNKNOWN

    def _get_threat_level(self, category: str) -> str:
        """Get threat level for signature category"""
        critical_categories = [
            'syscall', 'socket_creation', 'exec_functions'
        ]
        high_categories = [
            'stack_pivot', 'jmp_table', 'network_api'
        ]

        if any(c in category for c in critical_categories):
            return 'CRITICAL'
        elif any(c in category for c in high_categories):
            return 'HIGH'
        return 'MEDIUM'

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0

        byte_counts = Counter(data)
        entropy = 0.0
        for count in byte_counts.values():
            freq = count / len(data)
            entropy -= freq * (freq ** 0.5)

        return entropy

    def classify_shellcode(self, data: bytes) -> Dict[str, any]:
        """Classify shellcode type and characteristics"""
        analysis = self.analyze_shellcode_region(data)
        detections = analysis['detections']

        shellcode_type = ShellcodeType.UNKNOWN
        confidence = 0

        # Classify based on detected signatures
        if any(d.get('category') == 'socket_creation' for d in detections):
            shellcode_type = ShellcodeType.BIND_SHELL if any(
                d.get('signature', '').find('bind') != -1 for d in detections
            ) else ShellcodeType.REVERSE_SHELL
            confidence = 85

        elif any(d.get('category') == 'exec_functions' for d in detections):
            shellcode_type = ShellcodeType.EXEC_COMMAND
            confidence = 80

        elif any(d.get('signature') and 'DownloadString' in d.get('description', '') 
                 for d in detections):
            shellcode_type = ShellcodeType.DOWNLOADER
            confidence = 75

        else:
            confidence = len(detections) * 10

        return {
            'type': shellcode_type.value,
            'confidence': min(confidence, 100),
            'architecture': analysis['architecture'],
            'size': analysis['size'],
            'md5': analysis['md5'],
            'sha256': analysis['sha256'],
            'entropy': analysis['entropy'],
            'detections_count': len(detections),
        }

    def extract_shellcode_candidates(self, data: bytes, min_size: int = 32,
                                     entropy_threshold: float = 6.0) -> List[Dict]:
        """Extract potential shellcode regions from memory"""
        candidates = []

        # Method 1: Detect code after NOP sleds
        nop_sleds = self._detect_nop_sleds(data)
        for sled in nop_sleds:
            start = sled['offset'] + sled['size']
            # Extract following bytes until low entropy or next sled
            if start < len(data):
                for end in range(start + min_size, min(start + 512, len(data))):
                    chunk = data[start:end]
                    if self._calculate_entropy(chunk) > entropy_threshold:
                        candidates.append({
                            'source': 'nop_sled_payload',
                            'offset': start,
                            'size': end - start,
                            'entropy': round(self._calculate_entropy(chunk), 2),
                        })
                        break

        # Method 2: Detect after syscall instructions
        for sig_match in self._scan_signatures(data):
            if 'syscall' in sig_match.get('category', ''):
                start = sig_match['offset'] + 2
                if start < len(data):
                    chunk = data[start:min(start+256, len(data))]
                    candidates.append({
                        'source': 'syscall_context',
                        'offset': start,
                        'size': len(chunk),
                        'entropy': round(self._calculate_entropy(chunk), 2),
                    })

        return candidates

    def generate_report(self, analysis: Dict) -> str:
        """Generate human-readable shellcode analysis report"""
        report = []
        report.append("=" * 70)
        report.append("SHELLCODE ANALYSIS REPORT")
        report.append("=" * 70)
        report.append("")

        report.append("BASIC INFORMATION:")
        report.append(f"  Base Address: {analysis['base_address']}")
        report.append(f"  Size: {analysis['size']} bytes")
        report.append(f"  MD5: {analysis['md5']}")
        report.append(f"  SHA256: {analysis['sha256']}")
        report.append("")

        report.append("CHARACTERISTICS:")
        report.append(f"  Entropy: {analysis['entropy']}")
        report.append(f"  Architecture: {analysis['architecture']}")
        report.append(f"  Suspicious: {analysis['suspicious']}")
        report.append("")

        if analysis['detections']:
            report.append("DETECTIONS:")
            for i, detection in enumerate(analysis['detections'], 1):
                report.append(f"  [{i}] {detection.get('description', 'Unknown')}")
                report.append(f"      Offset: {hex(detection['offset'])}")
                report.append(f"      Threat Level: {detection['threat_level']}")
                report.append("")
        else:
            report.append("DETECTIONS: None")

        report.append("=" * 70)
        return "\n".join(report)
