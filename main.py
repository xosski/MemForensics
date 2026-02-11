#!/usr/bin/env python3
"""
Advanced Memory Forensic Toolkit with GUI
Integrates memory analysis, process scanning, and malware detection
"""

import sys
import os
import json
import csv
import hashlib
import struct
import gzip
import base64
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import re

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QLineEdit, QTextEdit, QFileDialog, QProgressBar, QComboBox,
    QCheckBox, QSpinBox, QListWidget, QListWidgetItem, QSplitter,
    QMessageBox, QHeaderView, QDialog, QFormLayout, QListView,
    QDoubleSpinBox, QPlainTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QModelIndex
from PyQt6.QtGui import QColor, QFont, QIcon, QStandardItemModel, QStandardItem
import psutil

from memory_dumper import MemoryDumper
from file_carver import FileScarver, FileType
from unallocated_scanner import UnallocatedScanner
from system_scanner import SystemScanner, ThreatSeverity
from shellcode_detector import ShellcodeDetector, ShellcodeType, Architecture


class MemoryReader:
    """Core memory analysis engine"""

    def __init__(self):
        self.signatures = self._load_signatures()
        self.entropy_threshold = 7.5

    def _load_signatures(self) -> Dict:
        """Load malware signatures"""
        return {
            'shellcode': [
                b'\x55\x89\xe5',  # push ebp; mov ebp, esp
                b'\x90\x90\x90',  # NOP sled
                b'\xcc\xcc\xcc',  # INT3 sled (debugger breakpoint)
            ],
            'dll_patterns': [
                b'MZ\x90\x00',  # PE header variant
                b'MZ\x00\x00',  # Standard PE
            ],
            'api_calls': [
                b'CreateRemoteThread',
                b'WriteProcessMemory',
                b'VirtualAllocEx',
                b'GetProcAddress',
                b'LoadLibrary',
                b'SetWindowsHookEx',
            ],
            'network': [
                b'WinInet',
                b'InternetConnect',
                b'InternetOpenUrlA',
            ]
        }

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        entropy = 0.0
        for i in range(256):
            freq = data.count(bytes([i])) / len(data)
            if freq > 0:
                entropy -= freq * (freq ** 0.5)
        return entropy

    def find_signature_matches(self, data: bytes, category: str) -> List[Tuple[int, bytes]]:
        """Find matching signatures in memory"""
        matches = []
        for sig in self.signatures.get(category, []):
            offset = 0
            while True:
                offset = data.find(sig, offset)
                if offset == -1:
                    break
                matches.append((offset, sig))
                offset += 1
        return matches

    def detect_injected_code(self, data: bytes) -> Dict:
        """Detect code injection patterns"""
        findings = {
            'shellcode_detected': False,
            'suspicious_entropy': False,
            'api_call_hooks': [],
            'dll_loaded': False,
            'entropy_value': 0.0,
            'confidence': 0
        }

        # Check entropy
        entropy = self.calculate_entropy(data)
        findings['entropy_value'] = entropy
        if entropy > self.entropy_threshold:
            findings['suspicious_entropy'] = True
            findings['confidence'] += 30

        # Check for shellcode
        shellcode_matches = self.find_signature_matches(data, 'shellcode')
        if shellcode_matches:
            findings['shellcode_detected'] = True
            findings['confidence'] += 40

        # Check for API calls
        api_matches = self.find_signature_matches(data, 'api_calls')
        if api_matches:
            findings['api_call_hooks'] = api_matches[:5]  # Top 5
            findings['confidence'] += 20

        # Check for DLL loading
        dll_matches = self.find_signature_matches(data, 'dll_patterns')
        if dll_matches:
            findings['dll_loaded'] = True
            findings['confidence'] += 10

        return findings

    def analyze_memory_region(self, data: bytes, base_addr: int = 0) -> Dict:
        """Comprehensive memory region analysis"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'base_address': hex(base_addr),
            'size': len(data),
            'hash_md5': hashlib.md5(data).hexdigest(),
            'hash_sha256': hashlib.sha256(data).hexdigest(),
            'injection_analysis': self.detect_injected_code(data),
            'entropy': self.calculate_entropy(data),
            'ascii_strings': self._extract_strings(data, min_len=4),
            'unicode_strings': self._extract_unicode_strings(data, min_len=4),
        }
        return analysis

    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """Extract ASCII strings"""
        strings = []
        current = b''
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    strings.append(current.decode('ascii', errors='ignore'))
                current = b''
        if len(current) >= min_len:
            strings.append(current.decode('ascii', errors='ignore'))
        return strings[:50]  # Limit to first 50

    def _extract_unicode_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """Extract Unicode strings (UTF-16)"""
        strings = []
        try:
            for i in range(0, len(data) - 2, 2):
                if data[i] != 0 and data[i + 1] == 0:
                    current = b''
                    j = i
                    while j < len(data) - 1 and data[j + 1] == 0 and 32 <= data[j] <= 126:
                        current += data[j:j + 1]
                        j += 2
                    if len(current) >= min_len:
                        strings.append(current.decode('ascii', errors='ignore'))
        except:
            pass
        return strings[:50]


class ProcessAnalyzer:
    """Analyze running processes"""

    def __init__(self):
        self.reader = MemoryReader()

    def get_process_list(self) -> List[Dict]:
        """Get all running processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'status']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'status': proc.info['status'],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes

    def analyze_process(self, pid: int) -> Dict:
        """Analyze a specific process"""
        try:
            proc = psutil.Process(pid)
            info = {
                'pid': pid,
                'name': proc.name(),
                'status': proc.status(),
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'memory_info': dict(proc.memory_info()._asdict()),
                'open_files': [str(f) for f in proc.open_files()],
                'connections': [
                    {
                        'laddr': str(conn.laddr),
                        'raddr': str(conn.raddr),
                        'status': conn.status,
                        'type': str(conn.type)
                    } for conn in proc.connections()
                ],
                'threads': proc.num_threads(),
                'children': [{'pid': child.pid, 'name': child.name()} for child in proc.children()],
            }
            return info
        except Exception as e:
            return {'error': str(e)}

    def detect_suspicious_processes(self) -> List[Dict]:
        """Detect potentially suspicious processes"""
        suspicious = []
        suspicious_names = [
            'rundll32', 'regsvcs', 'regasm', 'InstallUtil',
            'powershell', 'cmd', 'cscript', 'wscript'
        ]

        for proc in self.get_process_list():
            if any(name.lower() in proc['name'].lower() for name in suspicious_names):
                suspicious.append(proc)

        return suspicious


class MemoryDumpAnalyzer(QThread):
    """Thread for analyzing memory dumps"""
    progress = pyqtSignal(int, str)
    completed = pyqtSignal(dict)

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
        self.reader = MemoryReader()

    def run(self):
        try:
            with open(self.file_path, 'rb') as f:
                chunk_size = 1024 * 1024  # 1MB chunks
                offset = 0
                results = []

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    analysis = self.reader.analyze_memory_region(chunk, offset)
                    results.append(analysis)

                    progress = (offset / os.path.getsize(self.file_path)) * 100
                    self.progress.emit(int(progress), f"Analyzed {offset / (1024*1024):.1f} MB")

                    offset += len(chunk)

                self.completed.emit({
                    'success': True,
                    'total_regions': len(results),
                    'results': results
                })
        except Exception as e:
            self.completed.emit({
                'success': False,
                'error': str(e)
            })


class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Memory Forensic Toolkit")
        self.setGeometry(100, 100, 1400, 900)
        self.process_analyzer = ProcessAnalyzer()
        self.memory_reader = MemoryReader()

        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()
        tabs = QTabWidget()

        # Tab 1: Live System Scan
        tabs.addTab(self.create_system_scan_tab(), "Live System Scan")

        # Tab 2: Live Process Analysis
        tabs.addTab(self.create_process_analysis_tab(), "Live Process Analysis")

        # Tab 3: Active Memory Dump
        tabs.addTab(self.create_memory_dump_tab(), "Active Memory Dump")

        # Tab 3: Memory Dump Analysis
        tabs.addTab(self.create_dump_analysis_tab(), "Memory Dump Analysis")

        # Tab 4: File Carving (Deleted Files)
        tabs.addTab(self.create_file_carving_tab(), "File Carving")

        # Tab 5: Unallocated Space Scanner
        tabs.addTab(self.create_unallocated_scanner_tab(), "Unallocated Space")

        # Tab 6: Signature Scanning
        tabs.addTab(self.create_signature_scanning_tab(), "Signature Scanning")

        # Tab 7: Shellcode Detection
        tabs.addTab(self.create_shellcode_detection_tab(), "Shellcode Detection")

        # Tab 8: System Health
        tabs.addTab(self.create_system_health_tab(), "System Health")

        layout.addWidget(tabs)
        central_widget.setLayout(layout)

    def create_system_scan_tab(self) -> QWidget:
        """Create live system scan tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Scan options
        options_layout = QHBoxLayout()
        self.scan_registry_check = QCheckBox("Scan Registry")
        self.scan_registry_check.setChecked(True)
        self.scan_filesystem_check = QCheckBox("Scan File System")
        self.scan_filesystem_check.setChecked(False)  # Can be slow
        self.scan_processes_check = QCheckBox("Scan Processes")
        self.scan_processes_check.setChecked(True)
        
        options_layout.addWidget(self.scan_registry_check)
        options_layout.addWidget(self.scan_filesystem_check)
        options_layout.addWidget(self.scan_processes_check)
        options_layout.addStretch()
        layout.addLayout(options_layout)

        # Scan button
        scan_btn = QPushButton("Start Full System Scan")
        scan_btn.clicked.connect(self.start_system_scan)
        layout.addWidget(scan_btn)

        # Progress
        self.system_scan_progress = QProgressBar()
        self.system_scan_label = QLabel("Ready")
        layout.addWidget(QLabel("Progress:"))
        layout.addWidget(self.system_scan_progress)
        layout.addWidget(self.system_scan_label)

        # Summary
        layout.addWidget(QLabel("Threat Summary:"))
        self.system_scan_summary = QTextEdit()
        self.system_scan_summary.setReadOnly(True)
        self.system_scan_summary.setMaximumHeight(100)
        layout.addWidget(self.system_scan_summary)

        # Results table
        layout.addWidget(QLabel("Findings:"))
        self.system_scan_results = QTableWidget()
        self.system_scan_results.setColumnCount(4)
        self.system_scan_results.setHorizontalHeaderLabels(
            ['Type', 'Severity', 'Path', 'Description']
        )
        self.system_scan_results.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self.system_scan_results)

        # Export button
        export_btn = QPushButton("Export Findings")
        export_btn.clicked.connect(self.export_system_scan_results)
        layout.addWidget(export_btn)

        widget.setLayout(layout)
        return widget

    def create_process_analysis_tab(self) -> QWidget:
        """Create process analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Controls
        control_layout = QHBoxLayout()
        refresh_btn = QPushButton("Refresh Process List")
        refresh_btn.clicked.connect(self.refresh_process_list)
        scan_suspicious_btn = QPushButton("Scan for Suspicious")
        scan_suspicious_btn.clicked.connect(self.scan_suspicious_processes)
        control_layout.addWidget(refresh_btn)
        control_layout.addWidget(scan_suspicious_btn)
        layout.addLayout(control_layout)

        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(3)
        self.process_table.setHorizontalHeaderLabels(['PID', 'Name', 'Status'])
        self.process_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.process_table.itemSelectionChanged.connect(self.on_process_selected)
        layout.addWidget(QLabel("Running Processes:"))
        layout.addWidget(self.process_table)

        # Process details
        layout.addWidget(QLabel("Process Details:"))
        self.process_details = QTextEdit()
        self.process_details.setReadOnly(True)
        self.process_details.setMaximumHeight(250)
        layout.addWidget(self.process_details)

        widget.setLayout(layout)
        self.refresh_process_list()
        return widget

    def create_dump_analysis_tab(self) -> QWidget:
        """Create dump analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # File selection
        file_layout = QHBoxLayout()
        self.dump_path_input = QLineEdit()
        self.dump_path_input.setPlaceholderText("Select memory dump file...")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_dump_file)
        analyze_btn = QPushButton("Analyze Dump")
        analyze_btn.clicked.connect(self.analyze_dump)
        file_layout.addWidget(self.dump_path_input)
        file_layout.addWidget(browse_btn)
        file_layout.addWidget(analyze_btn)
        layout.addLayout(file_layout)

        # Progress
        self.dump_progress = QProgressBar()
        self.dump_progress_label = QLabel("Ready")
        layout.addWidget(QLabel("Progress:"))
        layout.addWidget(self.dump_progress)
        layout.addWidget(self.dump_progress_label)

        # Results
        layout.addWidget(QLabel("Analysis Results:"))
        self.dump_results = QTextEdit()
        self.dump_results.setReadOnly(True)
        layout.addWidget(self.dump_results)

        # Export
        export_btn = QPushButton("Export Results as JSON")
        export_btn.clicked.connect(self.export_analysis_results)
        layout.addWidget(export_btn)

        widget.setLayout(layout)
        return widget

    def create_signature_scanning_tab(self) -> QWidget:
        """Create signature scanning tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Signature selection
        sig_layout = QHBoxLayout()
        sig_layout.addWidget(QLabel("Signature Type:"))
        self.sig_combo = QComboBox()
        self.sig_combo.addItems(['shellcode', 'dll_patterns', 'api_calls', 'network'])
        sig_layout.addWidget(self.sig_combo)

        file_input = QLineEdit()
        file_input.setPlaceholderText("Select file to scan...")
        browse_sig_btn = QPushButton("Browse")
        browse_sig_btn.clicked.connect(lambda: self.browse_file_for_scan(file_input))
        sig_layout.addWidget(file_input)
        sig_layout.addWidget(browse_sig_btn)

        scan_btn = QPushButton("Scan")
        scan_btn.clicked.connect(lambda: self.scan_signatures(file_input.text()))
        sig_layout.addWidget(scan_btn)
        layout.addLayout(sig_layout)

        # Results
        layout.addWidget(QLabel("Scan Results:"))
        self.scan_results = QListWidget()
        layout.addWidget(self.scan_results)

        widget.setLayout(layout)
        return widget

    def create_shellcode_detection_tab(self) -> QWidget:
        """Create shellcode detection and analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # File selection
        file_layout = QHBoxLayout()
        file_label = QLabel("Memory/Binary File:")
        self.shellcode_file_input = QLineEdit()
        self.shellcode_file_input.setPlaceholderText("Select file to analyze...")
        shellcode_browse_btn = QPushButton("Browse")
        shellcode_browse_btn.clicked.connect(self.browse_shellcode_file)
        file_layout.addWidget(file_label)
        file_layout.addWidget(self.shellcode_file_input)
        file_layout.addWidget(shellcode_browse_btn)
        layout.addLayout(file_layout)

        # Analysis options
        options_layout = QHBoxLayout()
        self.shellcode_extract_candidates = QCheckBox("Extract Shellcode Candidates")
        self.shellcode_extract_candidates.setChecked(True)
        self.shellcode_auto_classify = QCheckBox("Auto-Classify Shellcode Type")
        self.shellcode_auto_classify.setChecked(True)
        options_layout.addWidget(self.shellcode_extract_candidates)
        options_layout.addWidget(self.shellcode_auto_classify)
        options_layout.addStretch()
        layout.addLayout(options_layout)

        # Analyze button
        analyze_btn = QPushButton("Analyze for Shellcode")
        analyze_btn.clicked.connect(self.analyze_shellcode)
        layout.addWidget(analyze_btn)

        # Progress
        self.shellcode_progress = QProgressBar()
        self.shellcode_label = QLabel("Ready")
        layout.addWidget(QLabel("Progress:"))
        layout.addWidget(self.shellcode_progress)
        layout.addWidget(self.shellcode_label)

        # Detections table
        layout.addWidget(QLabel("Shellcode Detections:"))
        self.shellcode_detections_table = QTableWidget()
        self.shellcode_detections_table.setColumnCount(6)
        self.shellcode_detections_table.setHorizontalHeaderLabels(
            ['Offset', 'Type', 'Size', 'Threat Level', 'Category', 'Description']
        )
        self.shellcode_detections_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self.shellcode_detections_table)

        # Summary panel
        layout.addWidget(QLabel("Analysis Summary:"))
        self.shellcode_summary = QTextEdit()
        self.shellcode_summary.setReadOnly(True)
        self.shellcode_summary.setMaximumHeight(150)
        layout.addWidget(self.shellcode_summary)

        # Export buttons
        export_layout = QHBoxLayout()
        export_report_btn = QPushButton("Export Report")
        export_report_btn.clicked.connect(self.export_shellcode_report)
        export_json_btn = QPushButton("Export JSON")
        export_json_btn.clicked.connect(self.export_shellcode_json)
        export_layout.addWidget(export_report_btn)
        export_layout.addWidget(export_json_btn)
        export_layout.addStretch()
        layout.addLayout(export_layout)

        widget.setLayout(layout)
        return widget

    def create_memory_dump_tab(self) -> QWidget:
        """Create active memory dump tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Dump options
        options_layout = QHBoxLayout()
        self.dump_entire_memory = QCheckBox("Dump Entire Physical Memory")
        self.dump_entire_memory.setChecked(True)
        options_layout.addWidget(self.dump_entire_memory)

        pid_label = QLabel("PID (if dumping process):")
        self.dump_pid_input = QSpinBox()
        options_layout.addWidget(pid_label)
        options_layout.addWidget(self.dump_pid_input)
        layout.addLayout(options_layout)

        # Output file
        file_layout = QHBoxLayout()
        file_label = QLabel("Output File:")
        self.dump_output_input = QLineEdit()
        self.dump_output_input.setPlaceholderText("memory_dump.bin")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_dump_output)
        dump_btn = QPushButton("Start Memory Dump")
        dump_btn.clicked.connect(self.start_memory_dump)
        
        file_layout.addWidget(file_label)
        file_layout.addWidget(self.dump_output_input)
        file_layout.addWidget(browse_btn)
        file_layout.addWidget(dump_btn)
        layout.addLayout(file_layout)

        # Progress
        self.memory_dump_progress = QProgressBar()
        self.memory_dump_label = QLabel("Ready")
        layout.addWidget(QLabel("Dump Progress:"))
        layout.addWidget(self.memory_dump_progress)
        layout.addWidget(self.memory_dump_label)

        # Status
        self.memory_dump_status = QPlainTextEdit()
        self.memory_dump_status.setReadOnly(True)
        layout.addWidget(QLabel("Status:"))
        layout.addWidget(self.memory_dump_status)

        widget.setLayout(layout)
        return widget

    def create_file_carving_tab(self) -> QWidget:
        """Create file carving tab for deleted files"""
        widget = QWidget()
        layout = QVBoxLayout()

        # File selection
        file_layout = QHBoxLayout()
        self.carving_file_input = QLineEdit()
        self.carving_file_input.setPlaceholderText("Select disk image or file...")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_carving_file)
        file_layout.addWidget(self.carving_file_input)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)

        # File type selection
        types_layout = QHBoxLayout()
        types_layout.addWidget(QLabel("File Types:"))
        self.carving_types_check = {}
        for file_type in FileType:
            check = QCheckBox(file_type.value.upper())
            check.setChecked(True)
            self.carving_types_check[file_type] = check
            types_layout.addWidget(check)
        types_layout.addStretch()
        layout.addLayout(types_layout)

        # Controls
        control_layout = QHBoxLayout()
        carve_btn = QPushButton("Start Carving")
        carve_btn.clicked.connect(self.start_carving)
        preview_btn = QPushButton("Preview Selected")
        preview_btn.clicked.connect(self.preview_carved_file)
        recover_btn = QPushButton("Recover Selected")
        recover_btn.clicked.connect(self.recover_carved_files)
        export_btn = QPushButton("Export List")
        export_btn.clicked.connect(self.export_carved_files)
        control_layout.addWidget(carve_btn)
        control_layout.addWidget(preview_btn)
        control_layout.addWidget(recover_btn)
        control_layout.addWidget(export_btn)
        layout.addLayout(control_layout)

        # Progress
        self.carving_progress = QProgressBar()
        self.carving_label = QLabel("Ready")
        layout.addWidget(QLabel("Progress:"))
        layout.addWidget(self.carving_progress)
        layout.addWidget(self.carving_label)

        # Results
        layout.addWidget(QLabel("Carved Files:"))
        self.carved_files_table = QTableWidget()
        self.carved_files_table.setColumnCount(5)
        self.carved_files_table.setHorizontalHeaderLabels(
            ['Type', 'Offset', 'Size', 'Hash', 'Confidence']
        )
        self.carved_files_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self.carved_files_table)

        widget.setLayout(layout)
        return widget

    def create_unallocated_scanner_tab(self) -> QWidget:
        """Create unallocated space scanner tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # File selection
        file_layout = QHBoxLayout()
        self.unalloc_file_input = QLineEdit()
        self.unalloc_file_input.setPlaceholderText("Select disk image or device...")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_unalloc_file)
        file_layout.addWidget(self.unalloc_file_input)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)

        # Scan options
        options_layout = QHBoxLayout()
        options_layout.addWidget(QLabel("Start Sector:"))
        self.unalloc_start_sector = QSpinBox()
        options_layout.addWidget(self.unalloc_start_sector)
        
        options_layout.addWidget(QLabel("End Sector:"))
        self.unalloc_end_sector = QSpinBox()
        self.unalloc_end_sector.setMaximum(999999999)
        options_layout.addWidget(self.unalloc_end_sector)
        
        options_layout.addStretch()
        layout.addLayout(options_layout)

        # Scan button
        scan_btn = QPushButton("Start Scan")
        scan_btn.clicked.connect(self.start_unalloc_scan)
        layout.addWidget(scan_btn)

        # Progress
        self.unalloc_progress = QProgressBar()
        self.unalloc_label = QLabel("Ready")
        layout.addWidget(QLabel("Progress:"))
        layout.addWidget(self.unalloc_progress)
        layout.addWidget(self.unalloc_label)

        # Results
        layout.addWidget(QLabel("Artifacts Found:"))
        self.unalloc_results = QTableWidget()
        self.unalloc_results.setColumnCount(4)
        self.unalloc_results.setHorizontalHeaderLabels(
            ['Type', 'Sub-Type', 'Offset', 'Confidence']
        )
        self.unalloc_results.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self.unalloc_results)

        widget.setLayout(layout)
        return widget

    def create_system_health_tab(self) -> QWidget:
        """Create system health tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # System info
        layout.addWidget(QLabel("System Health Check:"))

        self.system_info = QTextEdit()
        self.system_info.setReadOnly(True)
        layout.addWidget(self.system_info)

        refresh_health_btn = QPushButton("Refresh System Info")
        refresh_health_btn.clicked.connect(self.update_system_health)
        layout.addWidget(refresh_health_btn)

        widget.setLayout(layout)
        self.update_system_health()
        return widget

    def refresh_process_list(self):
        """Refresh process list"""
        processes = self.process_analyzer.get_process_list()
        self.process_table.setRowCount(0)

        for proc in processes:
            row = self.process_table.rowCount()
            self.process_table.insertRow(row)
            self.process_table.setItem(row, 0, QTableWidgetItem(str(proc['pid'])))
            self.process_table.setItem(row, 1, QTableWidgetItem(proc['name']))
            self.process_table.setItem(row, 2, QTableWidgetItem(proc['status']))

    def on_process_selected(self):
        """Handle process selection"""
        selected = self.process_table.selectedItems()
        if selected:
            pid = int(self.process_table.item(selected[0].row(), 0).text())
            info = self.process_analyzer.analyze_process(pid)
            self.process_details.setText(json.dumps(info, indent=2))

    def scan_suspicious_processes(self):
        """Scan for suspicious processes"""
        suspicious = self.process_analyzer.detect_suspicious_processes()
        msg = "\n".join([f"[!] {p['name']} (PID: {p['pid']})" for p in suspicious])
        QMessageBox.information(
            self,
            "Suspicious Processes",
            msg if msg else "No suspicious processes detected."
        )

    def browse_dump_file(self):
        """Browse for dump file"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Memory Dump", "", "All Files (*)"
        )
        if path:
            self.dump_path_input.setText(path)

    def analyze_dump(self):
        """Analyze memory dump"""
        path = self.dump_path_input.text()
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "Error", "Please select a valid file")
            return

        self.analyzer_thread = MemoryDumpAnalyzer(path)
        self.analyzer_thread.progress.connect(self.on_analysis_progress)
        self.analyzer_thread.completed.connect(self.on_analysis_completed)
        self.analyzer_thread.start()

    def on_analysis_progress(self, progress: int, message: str):
        """Update analysis progress"""
        self.dump_progress.setValue(progress)
        self.dump_progress_label.setText(message)

    def on_analysis_completed(self, results: dict):
        """Handle analysis completion"""
        if results['success']:
            summary = f"Analysis Complete\n"
            summary += f"Total Regions: {results['total_regions']}\n\n"
            if results['results']:
                first = results['results'][0]
                summary += f"Sample Region Analysis:\n"
                summary += json.dumps(first, indent=2)
            self.dump_results.setText(summary)
        else:
            QMessageBox.critical(self, "Error", f"Analysis failed: {results.get('error')}")

    def browse_file_for_scan(self, input_widget):
        """Browse file for signature scanning"""
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if path:
            input_widget.setText(path)

    def scan_signatures(self, file_path: str):
        """Scan file for signatures"""
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Please select a valid file")
            return

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            sig_type = self.sig_combo.currentText()
            matches = self.memory_reader.find_signature_matches(data, sig_type)

            self.scan_results.clear()
            for offset, sig in matches[:100]:
                item = QListWidgetItem(
                    f"Offset: 0x{offset:X} - {sig.hex()}"
                )
                self.scan_results.addItem(item)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def update_system_health(self):
        """Update system health information"""
        import platform

        info = f"""System Information:
Platform: {platform.system()} {platform.release()}
Processor: {platform.processor()}
CPU Count: {psutil.cpu_count()}
CPU Usage: {psutil.cpu_percent(interval=1)}%
Memory Usage: {psutil.virtual_memory().percent}%
Disk Usage: {psutil.disk_usage('/').percent}%

Active Processes: {len(psutil.pids())}
"""
        self.system_info.setText(info)

    def export_analysis_results(self):
        """Export analysis results"""
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "", "JSON Files (*.json)"
        )
        if path:
            results = self.dump_results.toPlainText()
            with open(path, 'w') as f:
                f.write(results)
            QMessageBox.information(self, "Success", f"Results saved to {path}")

    # System Scan handlers
    def start_system_scan(self):
        """Start full system scan"""
        self.system_scan_results.setRowCount(0)
        scanner = SystemScanner()

        def progress_callback(progress, message):
            self.system_scan_progress.setValue(progress)
            self.system_scan_label.setText(message)

        try:
            self.system_scan_label.setText("Initializing scan...")
            findings = scanner.full_system_scan(
                scan_registry=self.scan_registry_check.isChecked(),
                scan_filesystem=self.scan_filesystem_check.isChecked(),
                scan_processes=self.scan_processes_check.isChecked(),
                progress_callback=progress_callback
            )

            # Update summary
            summary = scanner.get_severity_summary()
            summary_text = f"""Threat Summary:
Critical: {summary['CRITICAL']}
High: {summary['HIGH']}
Medium: {summary['MEDIUM']}
Low: {summary['LOW']}
Info: {summary['INFO']}
Total: {len(findings)}"""
            self.system_scan_summary.setText(summary_text)

            # Populate results
            for finding in findings:
                row = self.system_scan_results.rowCount()
                self.system_scan_results.insertRow(row)
                
                # Color code by severity
                severity_colors = {
                    'CRITICAL': QColor(255, 0, 0),
                    'HIGH': QColor(255, 128, 0),
                    'MEDIUM': QColor(255, 255, 0),
                    'LOW': QColor(128, 128, 255),
                    'INFO': QColor(200, 200, 200),
                }
                
                color = severity_colors.get(finding.severity.name, QColor(200, 200, 200))

                type_item = QTableWidgetItem(finding.finding_type)
                type_item.setBackground(color)
                self.system_scan_results.setItem(row, 0, type_item)

                severity_item = QTableWidgetItem(finding.severity.name)
                severity_item.setBackground(color)
                self.system_scan_results.setItem(row, 1, severity_item)

                path_item = QTableWidgetItem(finding.path)
                path_item.setBackground(color)
                self.system_scan_results.setItem(row, 2, path_item)

                desc_item = QTableWidgetItem(finding.description)
                desc_item.setBackground(color)
                self.system_scan_results.setItem(row, 3, desc_item)

            self.system_scan_label.setText(f"Scan complete: {len(findings)} findings")
            QMessageBox.information(self, "Success", f"Found {len(findings)} issues")

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def export_system_scan_results(self):
        """Export system scan results"""
        if self.system_scan_results.rowCount() == 0:
            QMessageBox.warning(self, "Error", "No scan results to export")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save Scan Results", "system_scan.json", 
            "JSON Files (*.json);;CSV Files (*.csv)"
        )
        if path:
            try:
                format_type = 'json' if path.endswith('.json') else 'csv'
                # Would need to save scanner object or rebuild findings list
                QMessageBox.information(self, "Success", f"Results saved to {path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    # Memory Dump handlers
    def browse_dump_output(self):
        """Browse for dump output location"""
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Memory Dump", "memory_dump.bin", "Binary Files (*.bin);;All Files (*)"
        )
        if path:
            self.dump_output_input.setText(path)

    def start_memory_dump(self):
        """Start memory dumping"""
        output_path = self.dump_output_input.text()
        if not output_path:
            QMessageBox.warning(self, "Error", "Please specify output file")
            return

        dumper = MemoryDumper()
        if not dumper.is_admin:
            QMessageBox.critical(
                self, "Error",
                "Administrator/Root privileges required for memory dump"
            )
            return

        def progress_callback(progress, message):
            self.memory_dump_progress.setValue(progress)
            self.memory_dump_label.setText(message)
            self.memory_dump_status.appendPlainText(message)

        try:
            self.memory_dump_status.clear()
            self.memory_dump_status.appendPlainText("Starting memory dump...")

            if self.dump_entire_memory.isChecked():
                if dumper.os_type == 'Windows':
                    success = dumper.dump_memory_windows(output_path, progress_callback)
                else:
                    success = dumper.dump_memory_linux(output_path, progress_callback)
            else:
                pid = self.dump_pid_input.value()
                success = dumper.dump_process_memory(pid, output_path, progress_callback)

            if success:
                QMessageBox.information(
                    self, "Success",
                    f"Memory dump completed: {output_path}"
                )
            else:
                QMessageBox.critical(self, "Error", "Memory dump failed")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # File carving handlers
    def browse_carving_file(self):
        """Browse for file to carve"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File/Image to Carve"
        )
        if path:
            self.carving_file_input.setText(path)

    def start_carving(self):
        """Start file carving"""
        file_path = self.carving_file_input.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Please select valid file")
            return

        # Get selected file types
        selected_types = [
            ft for ft, check in self.carving_types_check.items()
            if check.isChecked()
        ]

        if not selected_types:
            QMessageBox.warning(self, "Error", "Please select file types")
            return

        self.carved_files_table.setRowCount(0)
        self.scarver = FileScarver()  # Store scarver for recovery
        self.carving_source_file = file_path  # Store source file

        def progress_callback(progress, message):
            self.carving_progress.setValue(progress)
            self.carving_label.setText(message)

        try:
            self.carving_label.setText("Carving in progress...")
            files = self.scarver.carve_from_file(file_path, selected_types, progress_callback)
            self.carved_files_list = files  # Store for recovery

            # Populate table
            for file_info in files:
                row = self.carved_files_table.rowCount()
                self.carved_files_table.insertRow(row)
                self.carved_files_table.setItem(row, 0, QTableWidgetItem(file_info['type']))
                self.carved_files_table.setItem(row, 1, QTableWidgetItem(hex(file_info['offset'])))
                self.carved_files_table.setItem(row, 2, QTableWidgetItem(str(file_info['size'])))
                self.carved_files_table.setItem(row, 3, QTableWidgetItem(file_info['hash_md5'][:16]))
                self.carved_files_table.setItem(row, 4, QTableWidgetItem(f"{file_info['confidence']:.2f}"))

            self.carving_label.setText(f"Carving complete: {len(files)} files found")
            QMessageBox.information(self, "Success", f"Carved {len(files)} files")

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def preview_carved_file(self):
        """Preview selected carved file"""
        selected_rows = self.carved_files_table.selectedIndexes()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Please select a file to preview")
            return

        row = selected_rows[0].row()
        if not hasattr(self, 'carved_files_list') or row >= len(self.carved_files_list):
            QMessageBox.warning(self, "Error", "File data not available")
            return

        file_info = self.carved_files_list[row]
        
        try:
            with open(self.carving_source_file, 'rb') as f:
                f.seek(file_info['offset'])
                data = f.read(min(file_info['size'], 1024))  # First 1KB
            
            # Show preview
            preview_text = f"File Type: {file_info['type']}\n"
            preview_text += f"Offset: {hex(file_info['offset'])}\n"
            preview_text += f"Size: {file_info['size']} bytes\n"
            preview_text += f"MD5: {file_info['hash_md5']}\n"
            preview_text += f"Confidence: {file_info['confidence']:.2f}\n"
            preview_text += f"\nHex Preview (first 1KB):\n"
            preview_text += data.hex()
            
            # Create preview dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Preview: {file_info['type']} at {hex(file_info['offset'])}")
            dialog.setGeometry(100, 100, 800, 600)
            layout = QVBoxLayout()
            text_edit = QPlainTextEdit()
            text_edit.setPlainText(preview_text)
            text_edit.setReadOnly(True)
            layout.addWidget(text_edit)
            dialog.setLayout(layout)
            dialog.exec()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Preview failed: {str(e)}")

    def recover_carved_files(self):
        """Recover selected carved files"""
        if self.carved_files_table.rowCount() == 0:
            QMessageBox.warning(self, "Error", "No carved files to recover")
            return

        output_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if not output_dir:
            return

        if not hasattr(self, 'carved_files_list') or not hasattr(self, 'carving_source_file'):
            QMessageBox.warning(self, "Error", "Carving data not available")
            return

        def progress_callback(progress, message):
            self.carving_progress.setValue(progress)
            self.carving_label.setText(message)

        try:
            self.carving_label.setText("Recovering files...")
            self.scarver.recover_carved_files(
                self.carving_source_file,
                self.carved_files_list,
                output_dir,
                progress_callback
            )
            self.carving_label.setText(f"Recovery complete: {len(self.carved_files_list)} files recovered")
            QMessageBox.information(self, "Success", f"Files recovered to {output_dir}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def export_carved_files(self):
        """Export carved files list to JSON or CSV"""
        if not hasattr(self, 'carved_files_list') or not self.carved_files_list:
            QMessageBox.warning(self, "Error", "No carved files to export")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Carved Files List", "carved_files.json",
            "JSON Files (*.json);;CSV Files (*.csv)"
        )
        
        if not path:
            return

        try:
            if path.endswith('.csv'):
                with open(path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['type', 'offset', 'size', 'hash_md5', 'confidence', 'header'])
                    writer.writeheader()
                    writer.writerows(self.carved_files_list)
            else:
                with open(path, 'w') as f:
                    json.dump(self.carved_files_list, f, indent=2)
            
            QMessageBox.information(self, "Success", f"Exported to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # Unallocated space scanner handlers
    def browse_unalloc_file(self):
        """Browse for disk image"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Disk Image/Device"
        )
        if path:
            self.unalloc_file_input.setText(path)

    def start_unalloc_scan(self):
        """Start unallocated space scan"""
        file_path = self.unalloc_file_input.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Please select valid file")
            return

        self.unalloc_results.setRowCount(0)
        scanner = UnallocatedScanner()

        def progress_callback(progress, message):
            self.unalloc_progress.setValue(progress)
            self.unalloc_label.setText(message)

        try:
            self.unalloc_label.setText("Scanning in progress...")
            findings = scanner.scan_unallocated_space(
                file_path,
                self.unalloc_start_sector.value(),
                self.unalloc_end_sector.value() if self.unalloc_end_sector.value() > 0 else None,
                progress_callback
            )

            # Populate table
            for finding in findings:
                row = self.unalloc_results.rowCount()
                self.unalloc_results.insertRow(row)
                self.unalloc_results.setItem(row, 0, QTableWidgetItem(finding.get('type', 'Unknown')))
                self.unalloc_results.setItem(row, 1, QTableWidgetItem(finding.get('artifact_type', finding.get('file_type', 'N/A'))))
                self.unalloc_results.setItem(row, 2, QTableWidgetItem(hex(finding['offset'])))
                self.unalloc_results.setItem(row, 3, QTableWidgetItem(finding.get('confidence', 'Unknown')))

            self.unalloc_label.setText(f"Scan complete: {len(findings)} artifacts found")
            QMessageBox.information(self, "Success", f"Found {len(findings)} artifacts")

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


    # Shellcode detection handlers
    def browse_shellcode_file(self):
        """Browse for file to analyze for shellcode"""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Analyze for Shellcode"
        )
        if path:
            self.shellcode_file_input.setText(path)

    def analyze_shellcode(self):
        """Analyze file for shellcode"""
        file_path = self.shellcode_file_input.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Please select valid file")
            return

        self.shellcode_detections_table.setRowCount(0)
        detector = ShellcodeDetector()

        try:
            self.shellcode_label.setText("Reading file...")
            with open(file_path, 'rb') as f:
                data = f.read()

            self.shellcode_label.setText("Analyzing for shellcode...")
            
            # Detect shellcode
            detections = detector.detect_shellcode(data)
            
            # Extract candidates if requested
            candidates = []
            if self.shellcode_extract_candidates.isChecked():
                self.shellcode_label.setText("Extracting shellcode candidates...")
                candidates = detector.extract_shellcode_candidates(data)

            # Populate table
            for i, detection in enumerate(detections):
                row = self.shellcode_detections_table.rowCount()
                self.shellcode_detections_table.insertRow(row)
                
                offset = detection.get('offset', 0)
                det_type = detection.get('type', 'unknown')
                size = detection.get('size', 0)
                threat = detection.get('threat_level', 'MEDIUM')
                category = detection.get('category', detection.get('pattern', 'N/A'))
                desc = detection.get('description', '')

                self.shellcode_detections_table.setItem(row, 0, QTableWidgetItem(hex(offset)))
                self.shellcode_detections_table.setItem(row, 1, QTableWidgetItem(det_type))
                self.shellcode_detections_table.setItem(row, 2, QTableWidgetItem(str(size)))
                self.shellcode_detections_table.setItem(row, 3, QTableWidgetItem(threat))
                self.shellcode_detections_table.setItem(row, 4, QTableWidgetItem(str(category)))
                self.shellcode_detections_table.setItem(row, 5, QTableWidgetItem(desc))

                # Color code by threat level
                threat_colors = {
                    'CRITICAL': QColor(255, 0, 0),
                    'HIGH': QColor(255, 128, 0),
                    'MEDIUM': QColor(255, 255, 0),
                    'LOW': QColor(128, 128, 255),
                }
                color = threat_colors.get(threat, QColor(200, 200, 200))
                for col in range(self.shellcode_detections_table.columnCount()):
                    item = self.shellcode_detections_table.item(row, col)
                    if item:
                        item.setBackground(color)

            # Generate summary
            summary = f"""Analysis Summary:
Total Detections: {len(detections)}
Shellcode Candidates Extracted: {len(candidates)}

Threat Levels:
  Critical: {sum(1 for d in detections if d.get('threat_level') == 'CRITICAL')}
  High: {sum(1 for d in detections if d.get('threat_level') == 'HIGH')}
  Medium: {sum(1 for d in detections if d.get('threat_level') == 'MEDIUM')}
  Low: {sum(1 for d in detections if d.get('threat_level') == 'LOW')}

"""
            
            # Auto-classify if requested
            if self.shellcode_auto_classify.isChecked() and len(data) > 0:
                try:
                    analysis = detector.analyze_shellcode_region(data)
                    classification = detector.classify_shellcode(data)
                    summary += f"""Shellcode Classification:
Type: {classification['type']}
Confidence: {classification['confidence']}%
Architecture: {classification['architecture']}
Entropy: {classification['entropy']}
"""
                except:
                    pass

            self.shellcode_summary.setText(summary)
            self.shellcode_label.setText(
                f"Analysis complete: {len(detections)} detections found"
            )
            
            # Store for export
            self.shellcode_detections = detections
            self.shellcode_candidates = candidates

            QMessageBox.information(
                self, "Success",
                f"Found {len(detections)} shellcode indicators"
            )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Analysis failed: {str(e)}")

    def export_shellcode_report(self):
        """Export shellcode analysis report"""
        if not hasattr(self, 'shellcode_detections') or not self.shellcode_detections:
            QMessageBox.warning(self, "Error", "No detections to export")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "shellcode_report.txt",
            "Text Files (*.txt)"
        )
        if not path:
            return

        try:
            detector = ShellcodeDetector()
            report = detector.generate_report({
                'base_address': '0x0',
                'size': len(open(self.shellcode_file_input.text(), 'rb').read()),
                'md5': 'N/A',
                'sha256': 'N/A',
                'entropy': 0.0,
                'architecture': 'unknown',
                'detections': self.shellcode_detections,
                'suspicious': len(self.shellcode_detections) > 0,
            })

            with open(path, 'w') as f:
                f.write(report)
                f.write("\n\nDETAILED DETECTIONS:\n")
                f.write("=" * 70 + "\n")
                for det in self.shellcode_detections:
                    f.write(f"\nOffset: {hex(det.get('offset', 0))}\n")
                    f.write(f"Type: {det.get('type', 'Unknown')}\n")
                    f.write(f"Threat Level: {det.get('threat_level', 'Unknown')}\n")
                    f.write(f"Description: {det.get('description', 'N/A')}\n")

            QMessageBox.information(self, "Success", f"Report exported to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def export_shellcode_json(self):
        """Export shellcode detections as JSON"""
        if not hasattr(self, 'shellcode_detections') or not self.shellcode_detections:
            QMessageBox.warning(self, "Error", "No detections to export")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON", "shellcode_detections.json",
            "JSON Files (*.json)"
        )
        if not path:
            return

        try:
            export_data = {
                'file': self.shellcode_file_input.text(),
                'analysis_time': datetime.now().isoformat(),
                'total_detections': len(self.shellcode_detections),
                'detections': self.shellcode_detections,
                'candidates': getattr(self, 'shellcode_candidates', [])
            }

            with open(path, 'w') as f:
                json.dump(export_data, f, indent=2)

            QMessageBox.information(self, "Success", f"JSON exported to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
