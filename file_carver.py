"""
File carving module for recovering deleted images and videos
from unallocated disk space
"""

import os
import re
import hashlib
import threading
from typing import List, Dict, Tuple, Optional, Callable
from dataclasses import dataclass
from enum import Enum


class FileType(Enum):
    """Supported file types for carving"""
    JPEG = 'jpeg'
    PNG = 'png'
    GIF = 'gif'
    BMP = 'bmp'
    TIFF = 'tiff'
    MP4 = 'mp4'
    AVI = 'avi'
    MOV = 'mov'
    MKV = 'mkv'
    WEBM = 'webm'
    ZIP = 'zip'
    RAR = 'rar'
    PDF = 'pdf'


@dataclass
class FileSignature:
    """File signature for carving"""
    file_type: FileType
    header: bytes
    footer: Optional[bytes] = None
    footer_offset: Optional[int] = None
    extensions: List[str] = None

    def __post_init__(self):
        if self.extensions is None:
            self.extensions = [self.file_type.value]


class FileScarver:
    """Carve deleted files from disk"""

    def __init__(self):
        self.signatures = self._initialize_signatures()
        self.found_files = []

    def _initialize_signatures(self) -> Dict[FileType, FileSignature]:
        """Initialize file signatures for carving"""
        return {
            FileType.JPEG: FileSignature(
                file_type=FileType.JPEG,
                header=b'\xFF\xD8\xFF',
                footer=b'\xFF\xD9',
                extensions=['jpg', 'jpeg']
            ),
            FileType.PNG: FileSignature(
                file_type=FileType.PNG,
                header=b'\x89PNG\r\n\x1a\n',
                extensions=['png']
            ),
            FileType.GIF: FileSignature(
                file_type=FileType.GIF,
                header=b'GIF87a' + b'|' + b'GIF89a',
                extensions=['gif']
            ),
            FileType.BMP: FileSignature(
                file_type=FileType.BMP,
                header=b'BM',
                extensions=['bmp']
            ),
            FileType.TIFF: FileSignature(
                file_type=FileType.TIFF,
                header=b'II\x2A\x00' + b'|' + b'MM\x00\x2A',
                extensions=['tif', 'tiff']
            ),
            FileType.MP4: FileSignature(
                file_type=FileType.MP4,
                header=b'\x00\x00\x00\x18\x66\x74\x79\x70',
                extensions=['mp4', 'm4v']
            ),
            FileType.AVI: FileSignature(
                file_type=FileType.AVI,
                header=b'RIFF',  # AVI files start with RIFF
                extensions=['avi']
            ),
            FileType.MOV: FileSignature(
                file_type=FileType.MOV,
                header=b'\x00\x00\x00\x20\x66\x74\x79\x70',
                extensions=['mov']
            ),
            FileType.MKV: FileSignature(
                file_type=FileType.MKV,
                header=b'\x1A\x45\xDF\xA3',
                extensions=['mkv', 'mka', 'mks', 'mk3d']
            ),
            FileType.WEBM: FileSignature(
                file_type=FileType.WEBM,
                header=b'\x1A\x45\xDF\xA3',
                extensions=['webm']
            ),
            FileType.ZIP: FileSignature(
                file_type=FileType.ZIP,
                header=b'PK\x03\x04',
                extensions=['zip']
            ),
            FileType.PDF: FileSignature(
                file_type=FileType.PDF,
                header=b'%PDF',
                footer=b'%%EOF',
                extensions=['pdf']
            ),
        }

    def carve_from_file(self, file_path: str, file_types: List[FileType] = None,
                       progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Carve files from disk image or raw file"""
        if file_types is None:
            file_types = list(FileType)

        self.found_files = []
        file_size = os.path.getsize(file_path)

        try:
            with open(file_path, 'rb') as f:
                offset = 0
                chunk_size = 10 * 1024 * 1024  # 10MB chunks
                overlap = 1024 * 1024  # 1MB overlap for boundary cases

                while offset < file_size:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Carve files in this chunk
                    carved = self._carve_chunk(chunk, offset, file_types)
                    self.found_files.extend(carved)

                    if progress_callback:
                        progress = int((offset / file_size) * 100)
                        progress_callback(progress, f"Carved {len(self.found_files)} files")

                    # Move back for overlap
                    offset += chunk_size - overlap

        except Exception as e:
            print(f"Carving error: {e}")

        return self.found_files

    def _carve_chunk(self, chunk: bytes, base_offset: int, file_types: List[FileType]) -> List[Dict]:
        """Carve files from a chunk of data"""
        carved_files = []

        for file_type in file_types:
            if file_type not in self.signatures:
                continue

            sig = self.signatures[file_type]
            offset = 0

            while True:
                # Find header
                header_offset = chunk.find(sig.header, offset)
                if header_offset == -1:
                    break

                absolute_offset = base_offset + header_offset

                # Determine file size
                if sig.footer:
                    footer_offset = chunk.find(sig.footer, header_offset)
                    if footer_offset == -1:
                        # Try to estimate size
                        file_size = self._estimate_file_size(chunk, header_offset, file_type)
                    else:
                        file_size = footer_offset + len(sig.footer) - header_offset
                else:
                    file_size = self._estimate_file_size(chunk, header_offset, file_type)

                if file_size > 0:
                    carved_files.append({
                        'type': file_type.value,
                        'offset': absolute_offset,
                        'size': file_size,
                        'hash_md5': hashlib.md5(chunk[header_offset:header_offset + file_size]).hexdigest(),
                        'header': sig.header.hex(),
                        'confidence': self._calculate_confidence(chunk, header_offset, file_type)
                    })

                offset = header_offset + 1

        return carved_files

    def _estimate_file_size(self, chunk: bytes, start: int, file_type: FileType) -> int:
        """Estimate file size when footer not found"""
        # Based on file type
        estimates = {
            FileType.JPEG: 500 * 1024,      # ~500KB average
            FileType.PNG: 300 * 1024,       # ~300KB average
            FileType.GIF: 100 * 1024,       # ~100KB average
            FileType.BMP: 1024 * 1024,      # ~1MB average
            FileType.MP4: 50 * 1024 * 1024, # ~50MB average
            FileType.AVI: 100 * 1024 * 1024,# ~100MB average
        }

        return estimates.get(file_type, 5 * 1024 * 1024)  # Default 5MB

    def _calculate_confidence(self, chunk: bytes, offset: int, file_type: FileType) -> float:
        """Calculate confidence score for carved file"""
        confidence = 0.5  # Base confidence

        # Check for additional signatures
        if file_type == FileType.JPEG:
            # Look for JPEG markers
            if b'\xFF\xE0' in chunk[offset:offset + 100]:  # JFIF marker
                confidence += 0.25
            if b'\xFF\xDB' in chunk[offset:offset + 100]:  # DQT marker
                confidence += 0.15

        elif file_type == FileType.PNG:
            # Check for IHDR chunk
            if b'IHDR' in chunk[offset:offset + 20]:
                confidence += 0.4

        elif file_type in [FileType.MP4, FileType.MOV]:
            # Check for ftyp box
            if b'ftyp' in chunk[offset:offset + 20]:
                confidence += 0.4
            if b'mdat' in chunk[offset:offset + 100]:
                confidence += 0.1

        return min(confidence, 1.0)

    def recover_carved_files(self, source_file: str, carved_files: List[Dict],
                            output_dir: str, progress_callback: Optional[Callable] = None) -> bool:
        """Recover carved files to disk"""
        os.makedirs(output_dir, exist_ok=True)
        recovered = 0

        try:
            with open(source_file, 'rb') as f:
                for i, file_info in enumerate(carved_files):
                    try:
                        f.seek(file_info['offset'])
                        data = f.read(file_info['size'])

                        # Generate filename
                        filename = f"{file_info['type']}_{i:06d}_{file_info['hash_md5'][:8]}.{file_info['type']}"
                        output_path = os.path.join(output_dir, filename)

                        with open(output_path, 'wb') as out:
                            out.write(data)

                        recovered += 1

                        if progress_callback:
                            progress = int(((i + 1) / len(carved_files)) * 100)
                            progress_callback(progress, f"Recovered {recovered} files")

                    except Exception as e:
                        print(f"Error recovering {file_info}: {e}")

            return True
        except Exception as e:
            print(f"Recovery error: {e}")
            return False

    def validate_carved_file(self, file_path: str) -> Dict:
        """Validate carved file integrity"""
        try:
            file_size = os.path.getsize(file_path)

            with open(file_path, 'rb') as f:
                header = f.read(16)

            validation = {
                'path': file_path,
                'size': file_size,
                'header': header.hex(),
                'valid': False,
                'file_type': 'Unknown',
                'issues': []
            }

            # Check headers
            for file_type, sig in self.signatures.items():
                if header.startswith(sig.header):
                    validation['file_type'] = file_type.value
                    validation['valid'] = True

                    # Verify footer if applicable
                    if sig.footer:
                        with open(file_path, 'rb') as f:
                            f.seek(-len(sig.footer), 2)
                            footer = f.read(len(sig.footer))

                        if footer != sig.footer:
                            validation['valid'] = False
                            validation['issues'].append('Footer mismatch')

                    break

            return validation
        except Exception as e:
            return {'error': str(e)}

    def scan_disk_for_deleted_content(self, drive: str,
                                     progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Scan entire disk for deleted files (platform specific)"""
        import platform as plat

        if plat.system() == 'Windows':
            return self._scan_windows_unallocated(drive, progress_callback)
        else:
            return self._scan_linux_unallocated(drive, progress_callback)

    def _scan_windows_unallocated(self, drive: str, 
                                 progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Scan Windows unallocated space"""
        try:
            drive_path = f'\\\\.\\{drive}:'
            files = []

            with open(drive_path, 'rb') as f:
                # Get drive size
                import msvcrt
                import ctypes

                GENERIC_READ = 0x80000000
                FILE_SHARE_READ = 0x00000001
                OPEN_EXISTING = 3

                # Read in chunks
                chunk_size = 4 * 1024 * 1024  # 4MB
                offset = 0

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Carve in this chunk
                    carved = self._carve_chunk(chunk, offset, list(FileType))
                    files.extend(carved)

                    if progress_callback:
                        progress = int((offset / (1024 ** 3)) * 100)  # Rough estimate
                        progress_callback(progress, f"Scanned {offset / (1024**3):.2f} GB")

                    offset += chunk_size

            return files
        except Exception as e:
            print(f"Windows scan error: {e}")
            return []

    def _scan_linux_unallocated(self, device: str,
                               progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Scan Linux unallocated space"""
        try:
            files = []
            chunk_size = 4 * 1024 * 1024  # 4MB

            with open(device, 'rb') as f:
                offset = 0

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Carve in this chunk
                    carved = self._carve_chunk(chunk, offset, list(FileType))
                    files.extend(carved)

                    if progress_callback:
                        progress = int((offset / (1024 ** 3)) * 100)
                        progress_callback(progress, f"Scanned {offset / (1024**3):.2f} GB")

                    offset += chunk_size

            return files
        except Exception as e:
            print(f"Linux scan error: {e}")
            return []
