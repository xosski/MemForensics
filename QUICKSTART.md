# Quick Start Guide

## Installation (5 minutes)

### Windows
```bash
# 1. Open Command Prompt as Administrator
# 2. Navigate to MemForensics folder
cd C:\Users\YourUsername\Desktop\X12\MemForensics

# 3. Run setup
python setup.py

# 4. Launch toolkit
python main.py
```

### Linux
```bash
# 1. Navigate to MemForensics folder
cd ~/Desktop/X12/MemForensics

# 2. Run setup (requires sudo)
sudo python3 setup.py

# 3. Launch toolkit
sudo python3 main.py
```

## First Steps

### 1. Analyze Current System

**Tab: Live Process Analysis**
1. Click "Refresh Process List"
2. See all running processes
3. Click "Scan for Suspicious" to detect anomalies
4. Select a process to see detailed information

**Tab: System Health**
1. View CPU, memory, and disk usage
2. Check active process count

### 2. Dump Active Memory (Windows/Linux)

**Tab: Active Memory Dump**
1. Ensure running as Administrator/Root
2. Set output file (e.g., `C:\temp\memory.bin`)
3. Check "Dump Entire Physical Memory"
4. Click "Start Memory Dump"
5. Wait for completion (size-dependent, 5-30 minutes)

### 3. Analyze Memory Dump

**Tab: Memory Dump Analysis**
1. Click "Browse" and select memory.bin
2. Click "Analyze Dump"
3. Watch progress bar
4. Results show:
   - Entropy scores
   - Extracted strings
   - Suspicious patterns
5. Click "Export Results as JSON" to save

### 4. Recover Deleted Files

**Tab: File Carving**
1. Have a disk image ready (or full disk copy)
2. Click "Browse" and select image
3. Check desired file types (JPEG, PNG, MP4, etc.)
4. Click "Start Carving"
5. Results table populates with found files
6. Click "Recover Selected" to extract

### 5. Scan Unallocated Space

**Tab: Unallocated Space**
1. Select disk image
2. Optionally set sector range (leave empty for full scan)
3. Click "Start Scan"
4. Find:
   - Deleted file headers
   - Emails/URLs
   - Database records
   - Registry hives
5. Results show type, location, and confidence

## Common Workflows

### Quick System Check (5 minutes)
```
1. Live Process Analysis → Refresh → Scan for Suspicious
2. System Health → Check stats
```

### Incident Response (30 minutes)
```
1. Memory Dump → Dump entire memory
2. Memory Dump Analysis → Analyze dump
3. Live Process Analysis → Check running processes
4. Signature Scanning → Scan for malware
```

### Deleted File Recovery (1-2 hours)
```
1. File Carving → Select disk image
2. Select JPEG, PNG, MP4 types
3. Start carving
4. Recover found files
5. Validate recovered files
```

### Forensic Investigation (4+ hours)
```
1. Full memory dump
2. Full disk image analysis
3. Unallocated space scan
4. File carving
5. Signature scanning
6. Export comprehensive report
```

## Tips & Tricks

### Faster Memory Analysis
- Analyze chunks instead of full dump
- Focus on suspicious regions first
- Use entropy filtering

### Better File Recovery
- Include multiple file types
- Higher confidence = more reliable
- Recovered files may need validation

### Artifact Hunting
- Look for URLs and emails in unallocated space
- Check for deleted database records
- Search for registry hives

### Performance
- Close unnecessary programs before dumping memory
- Have adequate disk space (≥2x RAM size)
- Use SSD for faster analysis

## Troubleshooting

### "Administrator/Root required"
**Problem**: Cannot dump memory
**Solution**: 
- Windows: Right-click python, "Run as Administrator"
- Linux: Use `sudo python3 main.py`

### "Out of memory" during carving
**Problem**: Analysis crashes on large files
**Solution**:
- Reduce chunk size in file_carver.py
- Carve smaller disk sections separately
- Increase system RAM

### No files found in carving
**Problem**: Carving found no deleted files
**Solution**:
- Data may be overwritten
- Try adjacent sectors
- Try different file types
- Disk may be mostly clean

### Slow performance
**Problem**: Toolkit runs slowly
**Solution**:
- Close other programs
- Reduce chunk size
- Use faster storage device
- Process smaller regions

## Command Line Usage (Advanced)

### Dump Memory
```bash
python memory_dumper.py --output memory.bin --full
```

### Carve Files
```bash
python file_carver.py --input disk.img --types jpeg,png --output ./recovered
```

### Scan Unallocated
```bash
python unallocated_scanner.py --input disk.img --sectors 1000-2000
```

## File Locations

### Default Output
- Windows: `C:\Users\YourName\AppData\Local\Temp\`
- Linux: `/tmp/` or current directory

### Configuration
- Edit `main.py` for default settings
- Modify chunk sizes in individual modules
- Adjust timeout values as needed

## Getting Help

### Check Logs
```bash
# Windows: View error messages in CMD window
# Linux: Check terminal output
```

### Enable Verbose Mode
Edit `main.py` and add:
```python
DEBUG = True  # Show detailed messages
```

### Common Issues
See README.md for detailed troubleshooting

## Safety Reminders

- Always work on copies, not original evidence
- Document all actions taken
- Preserve chain of custody
- Backup results regularly
- Verify hash values of findings

## Next Steps

1. Read full README.md for detailed documentation
2. Explore each tab to understand capabilities
3. Practice with test images/dumps
4. Develop standard workflows
5. Document your procedures

## Need More Info?

- **README.md**: Full documentation
- **Module Reference**: Detailed function descriptions
- **Source Code**: Well-commented Python files
- **Sample Data**: Create test memory dumps

Good luck with your forensic analysis!
