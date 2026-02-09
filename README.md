# Advanced Memory Forensic Toolkit

A comprehensive, cross-platform memory forensics analysis platform with PyQt6 GUI. Integrates active memory acquisition, deleted file recovery, unallocated space scanning, process analysis, and malware detection.

## Features

### 1. Active Memory Dump
- **Full Memory Acquisition**: Dump entire physical RAM
  - Windows: Using WinPmem driver or Win32 API fallback
  - Linux: Using /proc/kcore, /dev/mem, or dd
- **Process Memory Dump**: Extract specific process memory space
- **Progress Tracking**: Real-time dump progress with statistics
- **Admin Detection**: Verifies required privileges before attempting dump

### 2. Memory Dump Analysis
- Chunk-based analysis of memory dumps (1MB regions)
- Shannon entropy calculation (detects obfuscation/encryption)
- String extraction:
  - ASCII strings (printable characters)
  - Unicode strings (UTF-16)
- Hash generation: MD5, SHA256 for quick identification
- Code injection detection
- Shellcode pattern matching
- API hook detection

### 3. File Carving
Recovers deleted images and videos from disk:
- **Supported Formats**:
  - Images: JPEG, PNG, GIF, BMP, TIFF
  - Videos: MP4, AVI, MOV, MKV, WebM
  - Documents: PDF, ZIP, RAR
- **Recovery Methods**:
  - Header-based carving
  - Footer validation for enhanced accuracy
  - Confidence scoring
  - Entropy-based validation
- **Batch Recovery**: Recover multiple files to output directory

### 4. Unallocated Space Scanner
Forensic artifact detection from unallocated disk space:
- **File Headers**: Detects deleted file signatures
- **Text Artifacts**:
  - URLs and email addresses
  - File paths (Windows and Linux)
- **Database Records**:
  - SQLite databases
  - Windows Registry hives
  - Event logs
- **Memory Structures**: Dumped heap and stack data
- **Sector-Based Scanning**: Scan specific disk ranges

### 5. Live Process Analysis
- Real-time process enumeration
- Detailed process information:
  - Memory usage (RSS, VMS, etc.)
  - Open file handles
  - Network connections
  - Thread count
  - Child processes
- Suspicious process detection
- Process relationship mapping

### 6. Signature Scanning
Malware pattern detection:
- Shellcode identification
- DLL injection patterns
- API call hooks
- Network communication signatures
- Registry persistence patterns
- Code cave detection
- Embedded executable detection

### 7. System Health Monitoring
- CPU usage and core count
- Memory statistics
- Disk usage metrics
- Active process monitoring

## System Requirements

### Windows
- Windows 7 or later
- Administrator privileges (for memory dumping)
- Python 3.8+
- Optional: WinPmem driver for improved memory acquisition

### Linux
- Linux kernel 3.0+
- Root privileges (for memory/device access)
- Python 3.8+
- Tools: dd, file, openssl

## Installation

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Install Optional Components

**Windows - WinPmem** (for faster memory dumps):
```
# Download from: https://github.com/Velocidex/WinPmem
# Place winpmem_mini_x64.exe in Program Files or current directory
```

**Linux - Volatility3** (for advanced analysis):
```bash
sudo apt-get install volatility3
pip install volatility3
```

### Step 3: Run the Application

**Windows**:
```bash
python main.py
```

**Linux**:
```bash
sudo python3 main.py  # Required for memory access
```

## Usage Guide

### Active Memory Dump

1. Open **Active Memory Dump** tab
2. Choose dump type:
   - **Dump Entire Physical Memory**: Captures all RAM
   - **Dump Process**: Specify PID to dump single process
3. Set output file path
4. Click **Start Memory Dump**
5. Monitor progress bar and status messages

*Note: Requires administrator/root privileges*

### Memory Dump Analysis

1. Open **Memory Dump Analysis** tab
2. Click **Browse** to select memory dump file
3. Click **Analyze Dump**
4. Monitor progress as toolkit processes chunks
5. Results display:
   - Entropy scores
   - Extracted strings
   - Hashes (MD5, SHA256)
   - Injection indicators
6. Click **Export Results as JSON** to save analysis

### File Carving

1. Open **File Carving** tab
2. Select disk image or raw file
3. Check desired file types (images/videos)
4. Click **Start Carving**
5. Results table shows:
   - File type
   - Disk offset
   - Size estimate
   - MD5 hash
   - Confidence score
6. Select files and click **Recover Selected** to extract

### Unallocated Space Scanning

1. Open **Unallocated Space** tab
2. Select disk image or device
3. Optionally specify sector range
4. Click **Start Scan**
5. Results show:
   - Artifact type (file header, text, database, memory)
   - Sub-type classification
   - Disk offset
   - Confidence rating
6. Export results for further analysis

### Live Process Analysis

1. Open **Live Process Analysis** tab
2. Click **Refresh Process List** to enumerate processes
3. Select process from table to view details
4. Details show:
   - Memory usage
   - Open files
   - Network connections
   - Threads
   - Children
5. Click **Scan for Suspicious** to detect anomalies

### Signature Scanning

1. Open **Signature Scanning** tab
2. Select signature type
3. Select file to scan
4. Click **Scan**
5. Results show matching offsets and signatures

## Advanced Features

### Entropy Analysis
Detects obfuscation and encryption:
- Entropy > 7.5: Highly suspicious (encrypted/obfuscated)
- Entropy 6.0-7.5: Suspicious
- Entropy < 6.0: Normal data patterns

### Threat Scoring
Automated threat assessment based on:
- Malware signature matches
- Behavioral anomalies
- Entropy levels
- API patterns
- Process relationships

Threat Levels: Low, Medium, High, Critical

### Pattern Matching

**Shellcode Indicators**:
- Stack frame setup patterns
- NOP sleds (instruction padding)
- INT3 debugging breakpoints

**Injection Vectors**:
- CreateRemoteThread calls
- VirtualAllocEx/WriteProcessMemory patterns
- SetWindowsHookEx API usage

**Persistence Mechanisms**:
- Registry Run key paths
- Scheduled task artifacts
- Service installation patterns

## Output Formats

- **JSON**: Machine-readable analysis results
- **CSV**: Spreadsheet-compatible artifact lists
- **Text Reports**: Human-readable summaries
- **Forensic Timeline**: Chronological artifact listing

## Performance Notes

- **Memory Dumps**: 1-10 minutes for full system RAM (depends on size)
- **File Carving**: 10-30 minutes per GB of data
- **Unallocated Scanning**: 5-20 minutes per GB
- Parallel processing supported for large datasets

## Supported Platforms

- Windows 7, 8, 10, 11
- Linux (Ubuntu, Debian, CentOS, Fedora)
- macOS (partial support)

## Troubleshooting

### Memory Dump Fails on Windows
```
Error: "Administrator privileges required"
Solution: Run cmd as Administrator, then execute main.py
```

### Memory Dump Fails on Linux
```
Error: "Permission denied" reading /dev/mem
Solution: Run with sudo: sudo python3 main.py
```

### File Carving Finds No Files
```
Likely Causes:
1. Disk sectors already overwritten
2. Selected file types not present
3. Highly fragmented files

Solution: Try different file types or expand sector range
```

### High Memory Usage During Analysis
```
Solution: Process smaller chunks at a time
Edit chunk_size variable in memory_dumper.py or file_carver.py
```

## Legal Notice

This toolkit is designed for authorized forensic analysis and incident response. Ensure you have proper legal authorization before:
- Dumping memory on systems you do not own
- Accessing unallocated disk space
- Analyzing files/images

Unauthorized access to computer systems is illegal.

## Module Reference

### memory_dumper.py
`MemoryDumper` class - Active memory acquisition
- `dump_memory_windows()` - Windows full memory dump
- `dump_memory_linux()` - Linux full memory dump
- `dump_process_memory()` - Extract process address space

### file_carver.py
`FileScarver` class - Deleted file recovery
- `carve_from_file()` - Extract deleted files
- `recover_carved_files()` - Write recovered files to disk
- `validate_carved_file()` - Verify file integrity

### unallocated_scanner.py
`UnallocatedScanner` class - Artifact detection
- `scan_unallocated_space()` - Scan for forensic artifacts
- `analyze_unallocated_cluster()` - Detailed cluster analysis
- `generate_report()` - Create summary report

### advanced_scanner.py
`AdvancedScanner` class - Malware detection
- `scan_for_patterns()` - Signature matching
- `detect_anomalies()` - Behavioral analysis
- `analyze_memory_region()` - Comprehensive analysis

### volatility_integration.py
`VolatilityWrapper` class - Volatility3 integration
- `run_pslist()` - Process enumeration
- `run_malfind()` - Code injection detection
- `run_netscan()` - Network connections

## Contributing

To extend the toolkit:
1. Add new file type signatures in `file_carver.py`
2. Create new pattern detectors in `advanced_scanner.py`
3. Add artifact types in `unallocated_scanner.py`

## License

This toolkit is provided as-is for authorized forensic use.

## Contact/Support

For issues, create detailed bug reports with:
1. Operating system and Python version
2. Error message and traceback
3. Steps to reproduce
4. Sample data (if possible)
