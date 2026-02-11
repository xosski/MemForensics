# Shellcode Detection Module

Advanced shellcode detection and analysis capabilities for MemForensics.

## Overview

The new **Shellcode Detection** feature provides comprehensive analysis of binary files and memory dumps to identify, classify, and analyze shellcode payloads commonly used in exploits.

## Features

### 1. Signature-Based Detection
Detects known shellcode patterns:
- **Syscall Instructions**: x86/x64 `int 0x80`, `syscall`, `sysenter`
- **Stack Pivot Patterns**: `pop rsp; ret`, `pop rbp; ret`, etc.
- **NOP Sleds**: Single-byte (0x90) and multi-byte NOP patterns
- **Jump Tables**: Indirect jumps used in code execution
- **Socket APIs**: Network communication functions (`socket`, `connect`, `bind`)
- **Execution Functions**: Process creation (`CreateProcess`, `execve`, `WinExec`)

### 2. Heuristic Analysis
Behavioral pattern detection:
- **Function Prologues**: x86/x64 stack frame setup
- **Stack Adjustments**: Memory allocation patterns
- **High-Entropy Regions**: Encrypted/obfuscated shellcode detection
- **Instruction Patterns**: Conditional jumps, return instructions
- **Code Caves**: Null-byte sequences suitable for code injection

### 3. Known Payload Detection
Identifies specific malware families:
- **Meterpreter**: Metasploit payload detection
- **Reverse Shells**: Linux/Unix shell escape shellcode
- **Mimikatz**: Credential dumping tools
- **PowerShell Downloads**: Code execution frameworks

### 4. Classification & Analysis
Automatic shellcode type identification:
- **Reverse Shell**: Outbound connection to attacker
- **Bind Shell**: Listen for incoming connections
- **Exec Command**: Local command execution
- **Downloader**: Fetch and execute additional payloads
- **Privilege Escalation**: UAC/kernel exploitation
- **Code Cave**: Injected code in allocated space

## Usage

### Basic Analysis

1. Open **Shellcode Detection** tab
2. Click **Browse** and select memory dump or binary file
3. Select analysis options:
   - **Extract Shellcode Candidates**: Locate potential code payloads
   - **Auto-Classify Shellcode Type**: Identify exploit type
4. Click **Analyze for Shellcode**
5. Review results in the detections table

### Interpreting Results

**Offset**: Memory/file location of detection
**Type**: Detection method (signature, heuristic, known_payload, nop_sled, etc.)
**Size**: Bytes matched
**Threat Level**:
- **CRITICAL**: Syscalls, execution functions, known malware
- **HIGH**: Stack pivots, API hooks, network communication
- **MEDIUM**: Entropy anomalies, function prologues
- **LOW**: Generic code patterns

### Analysis Summary

The summary panel shows:
- Total detections
- Threat level breakdown
- Shellcode classification (type, confidence, architecture)
- Entropy analysis

## Export Formats

### Text Report
Human-readable analysis with:
- Detection summary
- Detailed listing per offset
- Threat assessment
- Recommendations

### JSON Export
Machine-readable format containing:
- All detections with metadata
- Extracted shellcode candidates
- Analysis timestamp
- Source file information

## Technical Details

### Supported Architectures

- **x86**: 32-bit Intel/AMD
- **x64**: 64-bit Intel/AMD (x86-64)
- **ARM**: ARM/Thumb (partial support)

### Detection Methods

| Method | Accuracy | Speed |
|--------|----------|-------|
| Signature | High (known patterns) | Fast |
| NOP Sled | High | Fast |
| Heuristic | Medium | Medium |
| Entropy | Medium (encrypted code) | Fast |
| Known Payload | Very High | Fast |

### Entropy Thresholds

- **> 7.5**: Highly suspicious (encrypted/obfuscated)
- **6.0-7.5**: Suspicious
- **< 6.0**: Normal data patterns

## Advanced Features

### Candidate Extraction

Automatically locates potential shellcode regions:
- Code following NOP sleds
- Regions after syscall instructions
- High-entropy areas in executable memory

### Architecture Detection

Identifies target architecture from instruction patterns:
- x64 syscalls and register operations
- x86 interrupt handlers and stack operations
- ARM Thumb instructions

### Custom Analysis

Create detailed profiles of shellcode regions:
```python
from shellcode_detector import ShellcodeDetector

detector = ShellcodeDetector()

# Analyze specific region
with open('memory_dump.bin', 'rb') as f:
    data = f.read()

# Full analysis
analysis = detector.analyze_shellcode_region(data)

# Classify type
classification = detector.classify_shellcode(data)

# Generate report
report = detector.generate_report(analysis)
print(report)
```

## Common Shellcode Patterns

### Reverse Shell (Linux)
```
mov eax, 0x66        ; socket syscall
mov ebx, 0x1         ; AF_INET
mov ecx, 0x1         ; SOCK_STREAM
int 0x80             ; syscall
```

### Bind Shell (Windows)
```
mov eax, [esp+4]    ; socket handle
lea ecx, [esp+8]    ; sockaddr
mov edx, 16         ; addrlen
call WSABind
```

### Code Cave Injection
```
90 90 90 90 90 90    ; NOP sled (padding)
55 89 e5             ; function prologue
83 ec 20             ; allocate stack space
```

## Performance

- **Small files (< 1 MB)**: < 1 second
- **Medium files (1-100 MB)**: 1-10 seconds
- **Large files (> 100 MB)**: 10-60 seconds

Processing speed depends on:
- File size
- Number of detections
- Candidate extraction (if enabled)
- System resources

## False Positives

Common sources of false positives:
- Legitimate code with similar patterns
- NOP padding in normal executables
- Stack frame setup in benign programs
- High-entropy legitimate data (images, video)

Reduce false positives by:
1. Correlating with other indicators
2. Checking process context
3. Analyzing parent process
4. Reviewing complete detection chain

## Troubleshooting

### No Detections Found
- File may be packed/encrypted (enable high-entropy detection)
- Shellcode variant not in database (update signatures)
- File is not actual memory dump

### Too Many False Positives
- Reduce detection sensitivity (filter by threat level)
- Focus on CRITICAL/HIGH findings
- Manual review of context

### Performance Issues
- Disable candidate extraction for large files
- Process smaller regions separately
- Increase entropy threshold

## References

- Shellcode Detection: https://en.wikipedia.org/wiki/Shellcode
- YARA Rules: https://virustotal.github.io/yara/
- Metasploit Payloads: https://docs.metasploit.com/

## API Reference

### ShellcodeDetector Class

**Methods**:
- `detect_shellcode(data)` - Comprehensive detection
- `analyze_shellcode_region(data, base_addr)` - Detailed analysis
- `classify_shellcode(data)` - Type classification
- `extract_shellcode_candidates(data)` - Locate code payloads
- `generate_report(analysis)` - Human-readable report

**Properties**:
- `signatures` - Detection pattern database
- `patterns` - Heuristic analysis patterns
- `known_payloads` - Malware family signatures

## Future Enhancements

Planned features:
- YARA rule integration
- Capstone disassembly integration
- Behavioral sandboxing analysis
- Machine learning classification
- Custom signature creation
- Shellcode variant tracking

## License

This module is part of MemForensics, provided for authorized forensic analysis.
