# Shellcode Detection - Quick Start Guide

## Installation
No additional setup needed. Shellcode detection is integrated into MemForensics.

## Running the Analysis

### Via GUI
1. Launch MemForensics: `python main.py`
2. Click **"Shellcode Detection"** tab
3. Click **"Browse"** and select a memory dump or binary file
4. Click **"Analyze for Shellcode"**
5. Review results in the table below

### Via Python API
```python
from shellcode_detector import ShellcodeDetector

# Create detector
detector = ShellcodeDetector()

# Load binary/memory dump
with open('memory_dump.bin', 'rb') as f:
    data = f.read()

# Detect shellcode
detections = detector.detect_shellcode(data)

# Print results
for detection in detections:
    print(f"[{detection['threat_level']}] {detection['description']}")
    print(f"  Offset: {hex(detection['offset'])}")
    print(f"  Type: {detection['type']}")
```

## Understanding Results

### Detection Table Columns

| Column | Meaning |
|--------|---------|
| **Offset** | Location in file (0x format) |
| **Type** | How it was detected (signature, heuristic, nop_sled, etc.) |
| **Size** | Number of bytes matched |
| **Threat Level** | CRITICAL/HIGH/MEDIUM/LOW |
| **Category** | Type of signature (syscall, socket, etc.) |
| **Description** | What was detected |

### Color Coding
- 🔴 **Red (CRITICAL)**: Known exploits, direct system calls
- 🟠 **Orange (HIGH)**: High-risk patterns, process injection
- 🟡 **Yellow (MEDIUM)**: Suspicious patterns, code anomalies
- 🔵 **Blue (LOW)**: Generic code patterns, normal functions

### Threat Levels

**CRITICAL** - Immediate concern:
- Syscall instructions (int 0x80, syscall)
- Known malware payloads
- Execution functions (CreateProcess, execve)

**HIGH** - Warrants investigation:
- Stack pivot gadgets
- NOP sleds
- API hooks
- Network APIs

**MEDIUM** - Suspicious but common:
- High-entropy regions
- Function prologues
- Jump patterns

**LOW** - Informational:
- Common instruction patterns
- Generic function setup

## Example Workflow

### Scenario 1: Analyze Memory Dump from Hacked System

```
1. Get memory dump:
   Windows: `python main.py` → Active Memory Dump tab
   Linux: `sudo python main.py` → Active Memory Dump tab

2. Analyze for shellcode:
   → Shellcode Detection tab
   → Browse to memory_dump.bin
   → Enable both options (extract + classify)
   → Click Analyze

3. Review results:
   - Check CRITICAL findings first
   - Look for shellcode type in summary
   - Note the architecture (x86/x64)

4. Extract findings:
   - Export as JSON for automation
   - Export as text report for documentation
```

### Scenario 2: Investigate Suspicious Binary

```
1. Obtain suspicious binary:
   - From email attachment
   - From network intrusion
   - From antivirus quarantine

2. Run shellcode analysis:
   - Shellcode Detection tab
   - Browse to binary file
   - Click Analyze

3. Check classification:
   - Is it recognized as known malware?
   - What architecture is it for?
   - What's the attack type (reverse shell, etc.)?

4. Take action:
   - If CRITICAL: Isolate system, escalate
   - If HIGH: Quarantine, collect logs
   - If MEDIUM: Monitor and investigate further
```

## Common Detections and What They Mean

### x86_syscall (CRITICAL)
```
int 0x80 - System call instruction
Meaning: Code is attempting to call kernel functions
Risk: Very high - direct kernel interaction
```

### x64_syscall (CRITICAL)
```
syscall - 64-bit system call
Meaning: Modern exploit for 64-bit systems
Risk: Very high - sophisticated attack
```

### nop_sled (HIGH)
```
90 90 90 90... (repeated 0x90 bytes)
Meaning: Padding before actual shellcode
Risk: High - classic exploit technique
```

### stack_pivot (HIGH)
```
pop rsp; ret - Change execution location
Meaning: Gadget for return-oriented programming
Risk: High - code execution without calling functions
```

### socket (CRITICAL)
```
socket, connect, bind, listen
Meaning: Network communication setup
Risk: Very high - likely reverse shell or data theft
```

### CreateProcess (CRITICAL)
```
Windows process creation function
Meaning: Spawning new processes
Risk: Very high - secondary malware or privilege escalation
```

## Tips for Analysis

### Reduce False Positives
1. Focus on **CRITICAL** and **HIGH** findings
2. Look for patterns, not isolated hits
3. Check if MULTIPLE suspicious indicators cluster together
4. Cross-reference with other forensic evidence

### Increase Detection Rate
1. Enable **Extract Shellcode Candidates** (slower but thorough)
2. Enable **Auto-Classify Shellcode Type** (helps identify intent)
3. Analyze **entire system memory** (not just single file)
4. Correlate with **process execution** information

### Best Practices
1. **Preserve evidence**: Keep original memory dumps
2. **Document findings**: Export reports for records
3. **Timeline**: Note when shellcode was likely injected
4. **Context**: Correlate with process trees and network logs
5. **Escalate**: Report CRITICAL findings to incident response team

## Interpreting the Summary Panel

```
Analysis Summary:
Total Detections: 47          ← How many matches found
Shellcode Candidates: 3        ← Potential injection sites

Threat Levels:
  Critical: 2                 ← Syscalls or known malware
  High: 8                     ← NOP sleds, stack pivots
  Medium: 22                  ← Entropy anomalies
  Low: 15                     ← Generic patterns

Shellcode Classification:
Type: reverse_shell           ← Likely attack type
Confidence: 85%               ← How confident in classification
Architecture: x64             ← 64-bit malware
Entropy: 6.45                 ← Encryption level
```

## Export Formats

### Text Report
```
======================================================================
SHELLCODE ANALYSIS REPORT
======================================================================

BASIC INFORMATION:
  Base Address: 0x400000
  Size: 65536 bytes
  MD5: a1b2c3d4e5f6...

CHARACTERISTICS:
  Entropy: 6.45
  Architecture: x64
  Suspicious: True

DETECTIONS:
  [1] Found x64_syscall signature
      Offset: 0x401234
      Threat Level: CRITICAL
...
```

### JSON Export
```json
{
  "file": "/path/to/memory.bin",
  "analysis_time": "2024-01-15T10:30:00",
  "total_detections": 47,
  "detections": [
    {
      "offset": 4202036,
      "type": "signature_match",
      "category": "x64_syscall",
      "threat_level": "CRITICAL",
      ...
    }
  ],
  "candidates": [...]
}
```

## Troubleshooting

### "No detections found"
- File might be heavily obfuscated/encrypted
- Shellcode variant not in database
- File is not a binary/memory dump
- **Solution**: Try with entropy detection enabled

### "Too many detections"
- Might be analyzing legitimate executable
- **Solution**: Filter by threat level (CRITICAL only)

### "Analysis takes too long"
- File is very large
- **Solution**: Disable candidate extraction, analyze in chunks

### "Uncertain about a finding"
- Check threat level (CRITICAL/HIGH = investigate)
- Look at the category (what triggered detection)
- Read the description carefully
- **Solution**: Cross-reference with other indicators

## Advanced Usage

### Command-Line Analysis
```python
#!/usr/bin/env python3
import sys
from shellcode_detector import ShellcodeDetector

detector = ShellcodeDetector()

with open(sys.argv[1], 'rb') as f:
    data = f.read()

analysis = detector.analyze_shellcode_region(data)
report = detector.generate_report(analysis)
print(report)

# Export JSON
import json
with open('analysis.json', 'w') as f:
    json.dump(analysis, f, indent=2)
```

### Batch Analysis
```python
import os
from shellcode_detector import ShellcodeDetector
from pathlib import Path

detector = ShellcodeDetector()

for file in Path('.').glob('*.bin'):
    with open(file, 'rb') as f:
        data = f.read()
    
    analysis = detector.analyze_shellcode_region(data)
    if analysis['suspicious']:
        print(f"[SUSPICIOUS] {file.name}")
        print(f"  Detections: {len(analysis['detections'])}")
```

## Next Steps

1. **Analyze** suspicious files/memory dumps
2. **Document** findings in the exported report
3. **Correlate** with other forensic evidence
4. **Report** critical findings to security team
5. **Remediate** based on findings (isolate, patch, etc.)

## Resources

- **Documentation**: See `SHELLCODE_DETECTION.md`
- **Implementation**: See `IMPLEMENTATION_NOTES.md`
- **Full Guide**: See `README.md` Shellcode Detection section
- **Tests**: Run `python test_shellcode_detector.py`

---

**Need Help?** Check the documentation files or review the test suite for examples.
