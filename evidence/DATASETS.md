# Digital Corpora Evidence Datasets

This directory contains forensic evidence datasets for testing and validation of SwiftProbe modules.

The latest repo update removed the bundled binary evidence from git history, so this folder is now documentation-only unless you add your own local datasets. Keep those datasets untracked.

## Available Datasets from Digital Corpora

### Disk Images

Digital Corpora (https://digitalcorpora.org/) provides various disk images for forensic research:

#### Raw Disk Images (.raw, .dd, .img)

1. **NIST Standalone Test Images** (Recommended for beginners)
   - Location: https://digitalcorpora.org/nist/disk-image-sets/
   - Files: Various small disk images (10MB-500MB) with known artifacts
   - Use Case: Testing disk carving, file recovery, file system analysis
   - Download: Download to `disk_images/` folder

2. **MFT Images** (Master File Table)
   - Location: https://digitalcorpora.org/nist/mft/
   - Files: NTFS MFT samples with deleted file entries
   - Use Case: Testing file recovery from MFT analysis
   - Download: Download to `disk_images/mft/`

3. **Bitlocker Encrypted Images**
   - Location: https://digitalcorpora.org/nist/bitlocker/
   - Files: Encrypted disk images with known passwords
   - Use Case: Testing encrypted evidence handling
   - Download: Download to `disk_images/encrypted/`

### Memory Dumps

1. **Volatility Memory Images**
   - Location: https://github.com/volatilityfoundation/volatility3/tree/develop/volatility3/tests/fixtures
   - Files: Sample memory dumps (.dmp, .mem)
   - Use Case: Testing process listing, network analysis, malware detection
   - Download: Download to `memory_dumps/` folder

2. **NIST Memory Images**
   - Location: https://digitalcorpora.org/nist/
   - Files: Real-world memory captures
   - Use Case: Advanced memory forensics
   - Download: Download to `memory_dumps/`

### Event Logs

1. **Windows Event Log Samples**
   - Location: https://github.com/EricZimmerman/evtx/tree/master/evtx/Resources
   - Files: .evtx files (Security, System, Application logs)
   - Use Case: Testing log parsing and timeline generation
   - Download: Download to `logs/windows/`

2. **Sysmon Logs**
   - Location: https://github.com/SwiftOnSecurity/sysmon-config
   - Files: Sysmon event logs with detailed process tracking
   - Use Case: Testing advanced process forensics
   - Download: Download to `logs/sysmon/`

---

## Directory Structure

```
evidence/
├── datasets/                    # Downloaded dataset metadata
├── disk_images/                 # Raw disk images for analysis
│   ├── nist/                   # NIST test images
│   ├── mft/                    # MFT samples
│   └── encrypted/              # Encrypted images
├── memory_dumps/                # Memory capture files
│   ├── windows/                # Windows memory dumps
│   └── linux/                  # Linux memory dumps (future)
├── logs/                        # Event logs and system logs
│   ├── windows/                # Windows Event Viewer logs (.evtx)
│   └── sysmon/                 # Sysmon event logs
└── DATASETS.md                 # This file
```

---

## Quick Start: Download Test Evidence

### Option 1: NIST Disk Images (Smallest, Quickest)
```bash
# Download a small 10MB test image
cd d:\PROJECTS\swiftProbe\evidence\disk_images
# Visit: https://digitalcorpora.org/nist/disk-image-sets/
# Download one of the "Raw" images (e.g., deben1.raw)
```

### Option 2: Create Test Evidence Locally
```bash
# Create a test disk image with known files
python -c "
import os
# Create test image with sample files
test_file = open('test_image.raw', 'wb')
test_file.write(b'\\xFF\\xD8\\xFF\\xE0' + b'\\x00' * 1000)  # Fake JPEG
test_file.write(b'\\x89PNG\\r\\n\\x1a\\n' + b'\\x00' * 1000)  # Fake PNG
test_file.close()
"
```

---

## Configuration for SwiftProbe

The backend is configured to look for evidence in these directories:

```python
# backend/config.py
EVIDENCE_PATHS = {
    'disk_images': 'evidence/disk_images/',
    'memory_dumps': 'evidence/memory_dumps/',
    'logs': 'evidence/logs/'
}
```

Update your module configuration to point to these paths:

```python
# backend/modules/disk_module.py
from pathlib import Path

DISK_IMAGES_DIR = Path(__file__).parent.parent.parent / 'evidence' / 'disk_images'

def scan_disk_image(image_name: str):
    image_path = DISK_IMAGES_DIR / image_name
    if not image_path.exists():
        raise FileNotFoundError(f"Disk image not found: {image_path}")
    # ... rest of implementation
```

The current repository layout already includes the evidence guidance files and ignore rules, so any images you download locally should stay inside ignored evidence subfolders.

---

## Testing Evidence

Once you have downloaded evidence files, test them with SwiftProbe:

```bash
# Test disk carving
python -c "
import sys
sys.path.insert(0, 'backend')
from modules.disk_module import scan_disk_image
results = scan_disk_image('test_image.raw')
print(f'Found {len(results)} artifacts')
"

# Test memory analysis
python -c "
import sys
sys.path.insert(0, 'backend')
from modules.ram_module import extract_processes
processes = extract_processes('evidence/memory_dumps/sample.dmp')
print(f'Found {len(processes)} processes')
"

# Test log parsing
python -c "
import sys
sys.path.insert(0, 'backend')
from modules.log_module import parse_event_log
events = parse_event_log('evidence/logs/windows/Security.evtx')
print(f'Parsed {len(events)} events')
"
```

---

## Legal and Ethical Considerations

- **Educational Use Only**: Digital Corpora images are for forensic training and research.
- **Source Documentation**: Always document the source and provenance of evidence.
- **Evidence Integrity**: Verify SHA-256 hashes after download to ensure integrity.
- **Chain of Custody**: SwiftProbe automatically logs all analysis operations for audit trails.

## Repository Notes

- The pre-existing sample evidence source referenced in the main README is the NIST CFReDS File Carving archive.
- Avoid committing raw evidence files, extracted samples, or downloads directories.
- Use this folder for provenance notes, hashes, and test instructions instead of storing large binaries in git.

---

## Resources

- **Digital Corpora Main Site**: https://digitalcorpora.org/
- **NIST Disk Images**: https://digitalcorpora.org/nist/disk-image-sets/
- **Volatility 3 Images**: https://github.com/volatilityfoundation/volatility3
- **File Signatures**: https://www.garykessler.net/library/file_sigs.html
- **Windows Event Log Reference**: https://www.ultimatewindowssecurity.com/

