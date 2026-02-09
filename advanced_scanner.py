"""
Advanced pattern scanning and malware detection module
"""

import re
import struct
from typing import List, Dict, Tuple, Optional
import hashlib
from enum import Enum


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class MalwarePattern:
    """Malware signature pattern"""

    def __init__(self, name: str, pattern: bytes, threat_level: ThreatLevel, 
                 description: str = ""):
        self.name = name
        self.pattern = pattern
        self.threat_level = threat_level
        self.description = description


class AdvancedScanner:
    """Advanced malware and anomaly detection"""

    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.yara_rules = self._load_yara_rules()

    def _initialize_patterns(self) -> List[MalwarePattern]:
        """Initialize malware detection patterns"""
        patterns = [
            # Injection patterns
            MalwarePattern(
                "VirtualAlloc Hook",
                b'\x55\x8b\xec\x83\xec.*\xc7\x45',
                ThreatLevel.HIGH,
                "Stack frame setup for memory allocation"
            ),
            MalwarePattern(
                "CreateRemoteThread",
                b'CreateRemoteThread',
                ThreatLevel.HIGH,
                "Process injection via remote thread"
            ),
            # Rootkit indicators
            MalwarePattern(
                "SSDT Hook",
                b'\x48\x8d\x15.*SSDT',
                ThreatLevel.CRITICAL,
                "System call table manipulation"
            ),
            # Obfuscation
            MalwarePattern(
                "XOR Obfuscation",
                b'[\x80-\xff]{2,}\x80[\x01-\x7f]',
                ThreatLevel.MEDIUM,
                "Potential XOR-based obfuscation"
            ),
            # Network communication
            MalwarePattern(
                "WinInet API",
                b'WinInet|InternetConnect|HTTPOpenRequest',
                ThreatLevel.MEDIUM,
                "Internet communication capability"
            ),
            # Persistence
            MalwarePattern(
                "Registry Persistence",
                b'\\Registry\\Machine\\Software\\Microsoft\\Windows\\Run',
                ThreatLevel.HIGH,
                "Registry-based persistence"
            ),
        ]
        return patterns

    def _load_yara_rules(self) -> Dict:
        """Load YARA rules for signature matching"""
        return {
            'trojan': {
                'patterns': [
                    b'trojan',
                    b'backdoor',
                    b'RAT',
                ],
                'threat_level': ThreatLevel.CRITICAL
            },
            'rootkit': {
                'patterns': [
                    b'ring0',
                    b'kernel_patch',
                    b'SSDT',
                ],
                'threat_level': ThreatLevel.CRITICAL
            },
            'worm': {
                'patterns': [
                    b'propagate',
                    b'replicate',
                    b'spread',
                ],
                'threat_level': ThreatLevel.HIGH
            },
            'ransomware': {
                'patterns': [
                    b'encrypt',
                    b'ransom',
                    b'bitcoin',
                    b'.locked',
                ],
                'threat_level': ThreatLevel.CRITICAL
            },
        }

    def scan_for_patterns(self, data: bytes) -> List[Dict]:
        """Scan data for malware patterns"""
        detections = []

        for pattern in self.patterns:
            if isinstance(pattern.pattern, bytes):
                if pattern.pattern in data:
                    detections.append({
                        'type': pattern.name,
                        'threat_level': pattern.threat_level.name,
                        'description': pattern.description,
                        'offset': data.find(pattern.pattern)
                    })

        return detections

    def detect_anomalies(self, data: bytes) -> List[Dict]:
        """Detect suspicious behavioral patterns"""
        anomalies = []

        # Check for suspicious byte sequences
        if self._detect_executable_in_data(data):
            anomalies.append({
                'type': 'Embedded Executable',
                'threat_level': ThreatLevel.HIGH.name,
                'description': 'PE executable found in data region'
            })

        # Check for code caves
        caves = self._find_code_caves(data)
        if caves:
            anomalies.append({
                'type': 'Code Cave',
                'threat_level': ThreatLevel.MEDIUM.name,
                'description': f'Found {len(caves)} potential code caves',
                'details': caves[:5]
            })

        # Check for API imports
        imports = self._extract_api_imports(data)
        if imports:
            anomalies.append({
                'type': 'API Imports',
                'threat_level': ThreatLevel.MEDIUM.name,
                'description': f'Found {len(imports)} API references',
                'imports': imports[:10]
            })

        return anomalies

    def _detect_executable_in_data(self, data: bytes) -> bool:
        """Detect if data contains executable code"""
        pe_signatures = [b'MZ\x90\x00', b'MZ\x00\x00', b'MZ']
        return any(sig in data for sig in pe_signatures)

    def _find_code_caves(self, data: bytes, min_size: int = 32) -> List[Tuple[int, int]]:
        """Find potential code caves (null byte sequences)"""
        caves = []
        current_offset = 0
        current_size = 0

        for i, byte in enumerate(data):
            if byte == 0x00:
                if current_size == 0:
                    current_offset = i
                current_size += 1
            else:
                if current_size >= min_size:
                    caves.append((current_offset, current_size))
                current_size = 0

        if current_size >= min_size:
            caves.append((current_offset, current_size))

        return caves

    def _extract_api_imports(self, data: bytes) -> List[str]:
        """Extract API function names from data"""
        api_names = [
            b'CreateFileA', b'CreateFileW',
            b'ReadFile', b'WriteFile',
            b'GetProcAddress', b'LoadLibraryA', b'LoadLibraryW',
            b'CreateRemoteThread', b'VirtualAllocEx',
            b'WriteProcessMemory', b'SetWindowsHookEx',
            b'InternetConnectA', b'InternetOpenUrlA',
        ]

        found_apis = []
        for api in api_names:
            if api in data:
                found_apis.append(api.decode('ascii', errors='ignore'))

        return found_apis

    def analyze_memory_region(self, data: bytes, base_addr: int = 0) -> Dict:
        """Comprehensive memory region analysis"""
        analysis = {
            'base_address': hex(base_addr),
            'size': len(data),
            'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'detections': self.scan_for_patterns(data),
            'anomalies': self.detect_anomalies(data),
            'entropy_score': self._calculate_entropy(data),
            'suspicious': False
        }

        # Mark as suspicious if detections found
        if analysis['detections'] or any(
            a['threat_level'] in ['HIGH', 'CRITICAL'] 
            for a in analysis['anomalies']
        ):
            analysis['suspicious'] = True

        return analysis

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0

        entropy = 0.0
        for i in range(256):
            freq = data.count(bytes([i])) / len(data)
            if freq > 0:
                entropy -= freq * (freq ** 0.5)

        return round(entropy, 2)

    def get_threat_summary(self, analysis_results: List[Dict]) -> Dict:
        """Generate threat summary from analysis results"""
        summary = {
            'total_regions': len(analysis_results),
            'suspicious_regions': 0,
            'critical_detections': 0,
            'high_detections': 0,
            'medium_detections': 0,
            'threat_level': ThreatLevel.LOW.name,
        }

        for result in analysis_results:
            if result['suspicious']:
                summary['suspicious_regions'] += 1

            for detection in result.get('detections', []):
                if detection['threat_level'] == ThreatLevel.CRITICAL.name:
                    summary['critical_detections'] += 1
                elif detection['threat_level'] == ThreatLevel.HIGH.name:
                    summary['high_detections'] += 1
                elif detection['threat_level'] == ThreatLevel.MEDIUM.name:
                    summary['medium_detections'] += 1

        # Determine overall threat level
        if summary['critical_detections'] > 0:
            summary['threat_level'] = ThreatLevel.CRITICAL.name
        elif summary['high_detections'] > 0:
            summary['threat_level'] = ThreatLevel.HIGH.name
        elif summary['medium_detections'] > 0:
            summary['threat_level'] = ThreatLevel.MEDIUM.name

        return summary
