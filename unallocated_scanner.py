"""
Unallocated disk space scanner module
Scans for deleted files, artifacts, and forensic evidence
"""

import os
import struct
import hashlib
from typing import List, Dict, Optional, Callable, Tuple
from dataclasses import dataclass
from enum import Enum


class ClusterState(Enum):
    """Cluster allocation state"""
    ALLOCATED = 'allocated'
    UNALLOCATED = 'unallocated'
    BAD = 'bad'
    RESERVED = 'reserved'


@dataclass
class DiskCluster:
    """Disk cluster information"""
    offset: int
    size: int
    state: ClusterState
    data: bytes = None


class UnallocatedScanner:
    """Scan unallocated disk space for artifacts"""

    def __init__(self):
        self.cluster_size = 4096  # Default 4KB clusters
        self.findings = []

    def scan_unallocated_space(self, file_path: str, start_sector: int = 0,
                              end_sector: Optional[int] = None,
                              progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Scan unallocated space for forensic artifacts"""
        findings = []

        try:
            file_size = os.path.getsize(file_path)

            if end_sector is None:
                end_sector = file_size // 512  # 512 byte sectors

            bytes_to_scan = (end_sector - start_sector) * 512

            with open(file_path, 'rb') as f:
                offset = start_sector * 512
                chunk_size = 1024 * 1024  # 1MB chunks
                scanned = 0

                while offset < file_size and scanned < bytes_to_scan:
                    f.seek(offset)
                    chunk = f.read(chunk_size)

                    if not chunk:
                        break

                    # Scan chunk for artifacts
                    artifacts = self._scan_chunk_for_artifacts(chunk, offset)
                    findings.extend(artifacts)

                    scanned += len(chunk)
                    offset += len(chunk)

                    if progress_callback:
                        progress = int((scanned / bytes_to_scan) * 100)
                        progress_callback(progress, f"Found {len(findings)} artifacts")

        except Exception as e:
            print(f"Scan error: {e}")

        self.findings = findings
        return findings

    def _scan_chunk_for_artifacts(self, chunk: bytes, base_offset: int) -> List[Dict]:
        """Scan chunk for forensic artifacts"""
        artifacts = []

        # Search for various artifacts
        artifacts.extend(self._find_file_headers(chunk, base_offset))
        artifacts.extend(self._find_text_artifacts(chunk, base_offset))
        artifacts.extend(self._find_database_records(chunk, base_offset))
        artifacts.extend(self._find_memory_structures(chunk, base_offset))

        return artifacts

    def _find_file_headers(self, chunk: bytes, base_offset: int) -> List[Dict]:
        """Find deleted file headers"""
        headers = {
            'JPEG': (b'\xFF\xD8\xFF', 'image/jpeg'),
            'PNG': (b'\x89PNG', 'image/png'),
            'GIF': (b'GIF8', 'image/gif'),
            'PDF': (b'%PDF', 'application/pdf'),
            'ZIP': (b'PK\x03\x04', 'application/zip'),
            'RAR': (b'Rar!\x1a\x07', 'application/x-rar'),
            'TIFF_LE': (b'II\x2A\x00', 'image/tiff'),
            'TIFF_BE': (b'MM\x00\x2A', 'image/tiff'),
            'MP4': (b'\x00\x00\x00\x20ftyp', 'video/mp4'),
            'AVI': (b'RIFF', 'video/x-avi'),
            'MKV': (b'\x1A\x45\xDF\xA3', 'video/x-matroska'),
            'DOCX': (b'PK\x03\x04\x14\x00\x06', 'application/vnd.openxmlformats'),
            'XLS': (b'\xD0\xCF\x11\xE0', 'application/vnd.ms-excel'),
        }

        artifacts = []

        for file_type, (header, mime_type) in headers.items():
            offset = 0
            while True:
                found = chunk.find(header, offset)
                if found == -1:
                    break

                absolute_offset = base_offset + found
                artifacts.append({
                    'type': 'File Header',
                    'file_type': file_type,
                    'mime_type': mime_type,
                    'offset': absolute_offset,
                    'header': header.hex(),
                    'context': chunk[found:min(found + 50, len(chunk))].hex()
                })

                offset = found + 1

        return artifacts

    def _find_text_artifacts(self, chunk: bytes, base_offset: int) -> List[Dict]:
        """Find text artifacts (URLs, emails, paths)"""
        artifacts = []

        # URLs
        url_pattern = b'http[s]?://[a-zA-Z0-9._/-]+'
        emails = self._find_pattern(chunk, rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        urls = self._find_pattern(chunk, b'http[s]?://[a-zA-Z0-9._/?#&=%-]+')

        for offset, text in urls + emails:
            try:
                artifacts.append({
                    'type': 'Text Artifact',
                    'artifact_type': 'URL/Email',
                    'offset': base_offset + offset,
                    'content': text.decode('utf-8', errors='ignore'),
                    'encoding': 'utf-8'
                })
            except:
                pass

        # File paths (Windows and Unix)
        paths = self._find_pattern(chunk, rb'[CcDdEe]:\\[a-zA-Z0-9._\\-]+')
        paths += self._find_pattern(chunk, rb'/[a-zA-Z0-9._/-]+')

        for offset, path in paths:
            try:
                artifacts.append({
                    'type': 'Text Artifact',
                    'artifact_type': 'File Path',
                    'offset': base_offset + offset,
                    'content': path.decode('utf-8', errors='ignore'),
                    'encoding': 'utf-8'
                })
            except:
                pass

        return artifacts[:50]  # Limit to first 50

    def _find_database_records(self, chunk: bytes, base_offset: int) -> List[Dict]:
        """Find database and structured data artifacts"""
        artifacts = []

        # SQLite header
        if b'SQLite format 3' in chunk:
            offset = chunk.find(b'SQLite format 3')
            artifacts.append({
                'type': 'Database',
                'database_type': 'SQLite',
                'offset': base_offset + offset,
                'confidence': 'High'
            })

        # Registry hive signatures
        if b'regf' in chunk[:100]:
            offset = chunk.find(b'regf')
            artifacts.append({
                'type': 'System Artifact',
                'artifact_type': 'Windows Registry Hive',
                'offset': base_offset + offset,
                'confidence': 'High'
            })

        # Event log signatures
        if b'ElfFile' in chunk:
            offset = chunk.find(b'ElfFile')
            artifacts.append({
                'type': 'System Artifact',
                'artifact_type': 'Windows Event Log',
                'offset': base_offset + offset,
                'confidence': 'High'
            })

        # Thumbs.db signature
        if b'JFIF' in chunk and b'Thumbs' in chunk:
            artifacts.append({
                'type': 'System Artifact',
                'artifact_type': 'Windows Thumbnail Cache',
                'offset': base_offset + chunk.find(b'JFIF'),
                'confidence': 'Medium'
            })

        return artifacts

    def _find_memory_structures(self, chunk: bytes, base_offset: int) -> List[Dict]:
        """Find dumped memory structures"""
        artifacts = []

        # Windows data structures
        signatures = {
            'MZ_Header': b'MZ\x90\x00',  # PE header
            'Win32_Heap': b'\x00\x10\x00\x00\x00\x10',
            'Unicode_String': b'\x00[\x00-\x7F][\x00[\x00-\x7F]]+',
        }

        for sig_name, signature in signatures.items():
            if signature in chunk:
                offset = chunk.find(signature)
                artifacts.append({
                    'type': 'Memory Structure',
                    'structure_type': sig_name,
                    'offset': base_offset + offset,
                    'confidence': 'Medium'
                })

        return artifacts

    def _find_pattern(self, chunk: bytes, pattern: bytes) -> List[Tuple[int, bytes]]:
        """Find pattern occurrences"""
        matches = []
        offset = 0

        while True:
            found = chunk.find(pattern, offset)
            if found == -1:
                break

            # Extract matched text
            end = found
            while end < len(chunk) and chunk[end] != 0:
                end += 1

            if end > found:
                matches.append((found, chunk[found:end]))

            offset = found + 1

        return matches

    def analyze_unallocated_cluster(self, file_path: str, offset: int,
                                   cluster_size: int = 4096) -> Dict:
        """Analyze a specific unallocated cluster"""
        try:
            with open(file_path, 'rb') as f:
                f.seek(offset)
                data = f.read(cluster_size)

            entropy = self._calculate_entropy(data)
            null_percentage = (data.count(b'\x00') / len(data)) * 100

            analysis = {
                'offset': offset,
                'size': len(data),
                'entropy': entropy,
                'null_percentage': null_percentage,
                'hash_md5': hashlib.md5(data).hexdigest(),
                'hash_sha256': hashlib.sha256(data).hexdigest(),
                'contains_data': null_percentage < 50,
                'suspicious': entropy > 7.0 or (0 < null_percentage < 50),
                'ascii_strings': self._extract_ascii_strings(data),
                'unicode_strings': self._extract_unicode_strings(data),
            }

            return analysis
        except Exception as e:
            return {'error': str(e)}

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

    def _extract_ascii_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """Extract ASCII strings"""
        strings = []
        current = b''

        for byte in data:
            if 32 <= byte <= 126:
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    strings.append(current.decode('ascii', errors='ignore'))
                current = b''

        if len(current) >= min_len:
            strings.append(current.decode('ascii', errors='ignore'))

        return strings[:20]

    def _extract_unicode_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """Extract Unicode strings (UTF-16)"""
        strings = []
        i = 0

        while i < len(data) - 2:
            if data[i] != 0 and data[i + 1] == 0 and 32 <= data[i] <= 126:
                current = b''
                j = i

                while j < len(data) - 1 and data[j + 1] == 0 and 32 <= data[j] <= 126:
                    current += data[j:j + 1]
                    j += 2

                if len(current) >= min_len:
                    strings.append(current.decode('ascii', errors='ignore'))

                i = j
            else:
                i += 1

        return strings[:20]

    def generate_report(self, findings: List[Dict]) -> Dict:
        """Generate summary report"""
        report = {
            'total_artifacts': len(findings),
            'by_type': {},
            'critical_findings': [],
            'suspicious_clusters': 0,
        }

        for finding in findings:
            ftype = finding.get('type', 'Unknown')
            report['by_type'][ftype] = report['by_type'].get(ftype, 0) + 1

            # Flag critical findings
            if finding.get('confidence') == 'High':
                report['critical_findings'].append(finding)

        return report
