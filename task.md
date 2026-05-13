# SwiftProbe: Forensic Digital Investigation Platform
## Complete Development Roadmap

---

## Phase 1: The Forensic Laboratory (Environment Setup)

**Goal:** Create a machine capable of handling raw binary data without crashing.

**Action:** Install the Python runtime, VS Code, and most importantly, the Sleuth Kit (TSK) binaries.

**Success Criteria:** You can run `import pytsk3` in a Python script without getting an error.

**Resource:** The Sleuth Kit Official Documentation: https://www.sleuthkit.org/sleuthkit/docs.php

---

## Phase 2: The Core Pipeline (Data Ingestion & Integrity)

**Goal:** Build the "Chain of Custody" foundation with secure file hashing and metadata management.

**Action:**
1. Program the `hasher.py` utility
2. Handle 1GB+ files by using chunking (avoid RAM exhaustion)
3. Generate SHA-256 hashes for evidence integrity
4. Connect to Supabase to persist metadata

**Success Criteria:**
- A file is hashed without excessive memory usage
- Metadata (filename, hash, timestamp) appears in Supabase `evidence_sources` table
- Supports incremental hashing for large files

**Resource:** Python Hashlib Documentation - https://docs.python.org/3/library/hashlib.html (focus on hash.update() for streaming)

---

## Phase 3: The Disk & Log Engine (Evidence Extraction)

**Goal:** Extract "Dead" data (data at rest) from disk images and logs.

**Action:**
1. **Disk Module:** Write logic in `disk_module.py` to scan for "Magic Numbers" (file signatures)
   - JPEG: `\xFF\xD8\xFF`
   - PNG: `\x89PNG`
   - PDF: `%PDF`
   - Other binary formats from Gary Kessler's table
   
2. **Log Module:** Use `python-evtx` to turn binary Windows event logs into JSON objects
   - Parse security, system, and application logs
   - Extract event IDs, timestamps, and descriptions

**Success Criteria:**
- Script finds deleted photos/files in sample .raw disk image
- File paths and recovery metadata saved to Supabase `recovered_files` table
- Windows event logs converted to JSON and queryable

**Resource:** 
- Gary Kessler's File Signature Table - https://www.garykessler.net/library/file_sigs.html
- python-evtx Documentation - https://github.com/williballenthin/python-evtx

---

## Phase 4: The Memory Engine (Live Analysis)

**Goal:** Analyze the "Heartbeat" of the system through memory dumps.

**Action:**
1. Integrate Volatility 3 framework
2. Call specific plugins programmatically via Python:
   - `windows.pslist.PsList` - Running processes
   - `windows.netstat.NetStat` - Network connections
   - `windows.handles.Handles` - Open files/handles
   
3. Parse plugin output into list of dictionaries for database storage

**Success Criteria:**
- Identify a specific running process (e.g., chrome.exe) from a memory dump
- Extract process PIDs, memory addresses, command lines
- Store process/network artifacts in Supabase `process_artifacts` table

**Resource:** 
- Volatility 3 Plugin Library - https://github.com/volatilityfoundation/volatility3/tree/develop/volatility3/framework/plugins
- Volatility 3 Documentation - https://volatility3.readthedocs.io/

---

## Phase 5: The API & Real-time Dashboard (Visualization)

**Goal:** Turn "Code" into a "Product" with live forensic progress tracking.

**Action:**
1. **Backend (Flask):**
   - Build routes to trigger disk scanning (`/api/scan-disk`)
   - Build routes to trigger memory analysis (`/api/analyze-memory`)
   - Build routes to retrieve indexed artifacts (`/api/artifacts`)
   - Implement WebSocket or Server-Sent Events for progress updates

2. **Frontend (React):**
   - Create Dashboard component for forensic operations
   - Use Supabase real-time subscriptions (`.on('postgres_changes', ...)`)
   - Show progress bars as backend finds files/processes
   - Display recovered files, artifacts in real-time tables

**Success Criteria:**
- Click button in browser → backend starts hashing/scanning
- Progress bars update in UI in real-time
- Artifacts "pop up" on screen automatically as they're found
- Multiple forensic operations can run in parallel

**Resource:** 
- Supabase Realtime Documentation - https://supabase.com/docs/guides/realtime
- Flask Real-time Updates - https://flask.palletsprojects.com/
- React Hooks & Context for state management

---

## Phase 6: The Forensic Finality (Reporting)

**Goal:** Generate legal, court-ready forensic reports.

**Action:**
1. Implement ReportLab logic
2. Pull all artifacts from Supabase tables (evidence_sources, recovered_files, process_artifacts)
3. Create court-ready PDF template with:
   - Case metadata (investigator, date, subject)
   - Verified hashes with chain of custody
   - Master timeline of events
   - Evidence inventory with recovered file details
   - Process/memory analysis findings
   - Digital signatures for authentication

**Success Criteria:**
- One-click generation of comprehensive forensic PDF
- PDF contains verified hashes, timelines, and all artifacts
- Template is professional and court-admissible

**Resource:** 
- ReportLab User Guide - https://www.reportlab.com/docs/reportlab-userguide.pdf (focus on Table and Flowable objects for timeline)

---

---

# Development Execution Plan: Step-by-Step Module Sequencing

## Overview: Dependency Chain

```
Phase 1: Environment Setup (Foundation)
    ↓
Phase 2: hasher.py (Core utility)
    ├→ Phase 3: disk_module.py + log_module.py (Evidence extraction)
    │   ├→ Phase 4: volatility integration (Memory analysis)
    │   │   ├→ Phase 5: Flask API + React Dashboard (Visualization)
    │   │   │   └→ Phase 6: reportlab generator (PDF output)
    └→ [Parallel] Supabase schema design (runs concurrently with modules)
```

---

## Development Sequence

### **STEP 1: Phase 1 - Environment Setup** ✓ PREREQUISITE
**When:** Start here
**Module(s):** N/A (system setup)
**What it does:** Installs Python, VS Code, Sleuth Kit, and required libraries
**Output:** Working Python environment with pytsk3 imported
**Next Step:** STEP 2

**Checklist:**
- [ ] Python 3.10+ installed
- [ ] VS Code with Python extension
- [ ] Sleuth Kit binaries installed (TSK)
- [ ] `pip install pytsk3` works without error
- [ ] Virtual environment created (`venv`)

---

### **STEP 2: Phase 2 - Core Hashing Engine** ✓ FOUNDATION MODULE
**When:** After Phase 1
**Module(s):** `backend/hasher.py` (NEW)
**What it does:**
- Reads large files in 64KB chunks
- Computes SHA-256 hash incrementally
- Returns hash + file metadata
- Stores result in Supabase `evidence_sources` table

**Dependencies:**
- Python hashlib (built-in)
- Supabase client (`supabase-py`)
- File system utilities

**Output:** 
- Function: `hash_file(filepath: str) -> dict` returns `{hash, filename, size, timestamp}`
- Database table created: `evidence_sources`

**Next Step:** STEP 3 & 4 (can run in parallel)

**Code Skeleton:**
```python
import hashlib
from supabase import create_client, Client

def hash_file(filepath: str, chunk_size: int = 65536) -> dict:
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256_hash.update(chunk)
    return {
        "hash": sha256_hash.hexdigest(),
        "filename": os.path.basename(filepath),
        "size": os.path.getsize(filepath),
        "timestamp": datetime.now().isoformat()
    }
```

---

### **STEP 3: Phase 3.1 - Disk Scanning Module** ⚡ FORENSIC ENGINE #1
**When:** After STEP 2
**Module(s):** `backend/modules/disk_module.py` (EXPAND)
**What it does:**
- Scans raw disk images (.raw, .dd, .img)
- Searches for file magic numbers (signatures)
- Recovers deleted files by signature
- Returns list of recovered files with offsets
- Stores results in Supabase `recovered_files` table

**Dependencies:**
- pytsk3 (from Phase 1)
- Gary Kessler's file signature database (hardcoded dict or external JSON)
- Supabase client

**Output:**
- Function: `scan_disk_image(image_path: str) -> list[dict]` returns list of recovered files
- Database table created: `recovered_files` with columns (id, image_path, file_signature, offset, file_type, recovery_status)

**Next Step:** STEP 4

**Code Skeleton:**
```python
import pytsk3

FILE_SIGNATURES = {
    "JPEG": (b"\xFF\xD8\xFF", b"\xFF\xD9"),
    "PNG": (b"\x89PNG", b"\x00IEND"),
    "PDF": (b"%PDF", b"%%EOF"),
    # ... more signatures
}

def scan_disk_image(image_path: str) -> list[dict]:
    recovered_files = []
    with open(image_path, "rb") as f:
        data = f.read()
        for sig_name, (start_sig, end_sig) in FILE_SIGNATURES.items():
            offset = 0
            while True:
                offset = data.find(start_sig, offset)
                if offset == -1:
                    break
                recovered_files.append({
                    "file_type": sig_name,
                    "offset": offset,
                    "image_path": image_path
                })
                offset += 1
    return recovered_files
```

---

### **STEP 4: Phase 3.2 - Log Parsing Module** ⚡ FORENSIC ENGINE #2
**When:** After STEP 2 (parallel with STEP 3)
**Module(s):** `backend/modules/log_module.py` (EXPAND)
**What it does:**
- Parses binary Windows event logs (.evtx)
- Converts to JSON objects
- Filters by event ID, timestamp, severity
- Extracts security events (logins, file access, etc.)
- Stores timeline in Supabase `event_timeline` table

**Dependencies:**
- python-evtx (`pip install python-evtx`)
- Supabase client

**Output:**
- Function: `parse_event_log(log_path: str) -> list[dict]` returns list of JSON events
- Database table created: `event_timeline` with columns (id, timestamp, event_id, source, message, severity)

**Next Step:** STEP 5 (after 3 & 4 both done)

**Code Skeleton:**
```python
import evtx

def parse_event_log(log_path: str) -> list[dict]:
    events = []
    for record in evtx.Evtx(log_path):
        event = record.xml()
        events.append({
            "timestamp": extract_timestamp(event),
            "event_id": extract_event_id(event),
            "source": extract_source(event),
            "message": extract_message(event)
        })
    return events
```

---

### **STEP 5: Phase 4 - Memory Analysis Module** 🧠 FORENSIC ENGINE #3
**When:** After STEPS 3 & 4 complete
**Module(s):** `backend/modules/ram_module.py` (EXPAND or NEW volatility_interface.py)
**What it does:**
- Integrates Volatility 3 framework
- Programmatically calls plugins (windows.pslist.PsList, windows.netstat.NetStat)
- Parses plugin output into structured dictionaries
- Stores process/network artifacts in Supabase `process_artifacts` table
- Enables live memory forensics on dump files

**Dependencies:**
- volatility3 (`pip install volatility3`)
- Supabase client

**Output:**
- Function: `extract_processes(dump_path: str) -> list[dict]` returns list of processes
- Function: `extract_netstat(dump_path: str) -> list[dict]` returns network connections
- Database table created: `process_artifacts` with columns (id, dump_path, pid, process_name, memory_address, command_line)

**Next Step:** STEP 6

**Code Skeleton:**
```python
from volatility3.framework import contexts, automagic, plugins
from volatility3.framework.layers import intel

def extract_processes(dump_path: str) -> list[dict]:
    ctx = contexts.Context()
    auto = automagic.AutomagicSequence(ctx)
    
    # Load memory dump
    automagic.choose_single_os(auto)
    
    # Get PsList plugin
    pslist = plugins.construct_plugin(ctx, windows.pslist.PsList)
    
    processes = []
    for process in pslist.generator(ctx):
        processes.append({
            "pid": process.pid,
            "name": process.name,
            "memory_address": hex(process.address)
        })
    return processes
```

---

### **STEP 6: Supabase Schema & Backend Core** 🗄️ DATABASE FOUNDATION
**When:** Parallel with STEPS 3-5 (or start early)
**Module(s):** `backend/core/supabase_db.py` (EXPAND)
**What it does:**
- Defines all database tables and schemas
- Handles connection pooling
- Provides ORM functions for CRUD operations
- Sets up real-time subscriptions
- Manages authentication

**Tables to Create:**
1. `evidence_sources` - Original files with hashes
2. `recovered_files` - Deleted files recovered from disks
3. `event_timeline` - Parsed Windows event logs
4. `process_artifacts` - Running processes from memory dumps
5. `forensic_cases` - Case metadata (investigator, date, subject)
6. `reports` - Generated PDF reports

**Dependencies:**
- supabase-py (`pip install supabase`)

**Output:**
- Connected Supabase client
- All tables created with proper indexes
- RLS (Row-Level Security) policies configured

**Next Step:** STEP 7

---

### **STEP 7: Phase 5.1 - Flask API Backend** 🔌 API LAYER
**When:** After STEPS 2-5 complete (can start once modules exist)
**Module(s):** `backend/app.py` (EXPAND)
**What it does:**
- Creates REST endpoints for forensic operations
- Routes for disk scanning: `POST /api/scan-disk`
- Routes for memory analysis: `POST /api/analyze-memory`
- Routes for artifact retrieval: `GET /api/artifacts`
- Background task execution (celery or threading)
- Real-time progress updates via WebSocket

**Endpoints to Create:**
```
POST   /api/scan-disk        → Trigger disk_module.scan_disk_image()
POST   /api/analyze-memory   → Trigger ram_module.extract_processes()
POST   /api/parse-logs       → Trigger log_module.parse_event_log()
POST   /api/hash-evidence    → Trigger hasher.hash_file()
GET    /api/artifacts        → Retrieve all recovered artifacts
GET    /api/artifacts/<id>   → Retrieve specific artifact
GET    /api/timeline         → Retrieve event timeline
GET    /api/status           → Check forensic operation status
```

**Dependencies:**
- Flask (`pip install flask`)
- Celery or APScheduler for background tasks
- Supabase client

**Output:**
- Working Flask server on `http://localhost:5000`
- All endpoints callable and returning JSON

**Next Step:** STEP 8

---

### **STEP 8: Phase 5.2 - React Frontend Dashboard** 🎨 UI LAYER
**When:** After STEP 7 (Flask API working)
**Module(s):** `frontend/src/` (CREATE components)
**What it does:**
- Displays forensic operations UI
- Shows real-time progress bars
- Lists recovered files/artifacts in tables
- Uses Supabase real-time subscriptions for live updates
- Handles user input for scan operations
- Displays case metadata and timeline

**Components to Create:**
1. `DashboardPage.jsx` - Main landing page
2. `ScanDiskPanel.jsx` - Disk scanning interface
3. `MemoryAnalysisPanel.jsx` - Memory dump interface
4. `ArtifactsList.jsx` - Recovered files table
5. `TimelineView.jsx` - Event timeline visualization
6. `CaseMetadata.jsx` - Case information form
7. `ReportGenerator.jsx` - PDF generation button

**Dependencies:**
- React 18+
- Supabase JS client (`npm install @supabase/supabase-js`)
- Vite (already configured)
- Tailwind CSS (already configured)

**Output:**
- Running React dashboard on `http://localhost:5173`
- Live updates from Supabase
- Connected to Flask API

**Next Step:** STEP 9

---

### **STEP 9: Real-time Integration** 🔄 LIVE DATA SYNC
**When:** After STEPS 7 & 8 complete
**Module(s):** Integration in `frontend/src/services/` and `backend/app.py`
**What it does:**
- Implements Supabase real-time subscriptions on frontend
- Backend publishes events to Supabase on file/process discovery
- UI automatically updates when new artifacts appear
- Progress tracking via database updates
- Notification system for completed scans

**Code Pattern:**
```javascript
// React Frontend
useEffect(() => {
  const channel = supabase
    .channel('recovered_files')
    .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'recovered_files' }, payload => {
      setArtifacts(prev => [...prev, payload.new])
    })
    .subscribe()
}, [])
```

**Output:**
- Live updates flowing from backend to frontend
- Artifacts appearing in real-time on UI

**Next Step:** STEP 10

---

### **STEP 10: Phase 6 - Report Generation Engine** 📄 FINAL OUTPUT
**When:** After STEPS 1-9 complete
**Module(s):** `backend/report_generator.py` (NEW)
**What it does:**
- Pulls all artifacts from Supabase tables
- Creates PDF using ReportLab
- Formats:
  - Title page with case metadata
  - Chain of custody section with hashes
  - Evidence inventory (recovered files)
  - Timeline of events
  - Process/memory findings
  - Digital signature for authentication
- Stores PDF reference in `reports` table
- Returns PDF to user for download

**Dependencies:**
- ReportLab (`pip install reportlab`)
- Supabase client

**Output:**
- Function: `generate_forensic_report(case_id: str) -> bytes` returns PDF file
- Endpoint: `GET /api/report/<case_id>` downloads PDF

**Code Skeleton:**
```python
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, Paragraph, Spacer

def generate_forensic_report(case_id: str) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    story = []
    
    # Fetch case data from Supabase
    case = supabase.table('forensic_cases').select('*').eq('id', case_id).single().execute()
    artifacts = supabase.table('recovered_files').select('*').eq('case_id', case_id).execute()
    timeline = supabase.table('event_timeline').select('*').eq('case_id', case_id).execute()
    
    # Build report
    story.append(Paragraph(f"Forensic Report: {case.subject}"))
    story.append(create_case_table(case))
    story.append(create_artifacts_table(artifacts.data))
    story.append(create_timeline_table(timeline.data))
    
    doc.build(story)
    return buffer.getvalue()
```

---

## Summary: What to Build First

| Step | Module | Priority | Why | Time Est |
|------|--------|----------|-----|----------|
| 1 | Environment Setup | CRITICAL | Foundation for all development | 1-2 hrs |
| 2 | hasher.py | CRITICAL | Core utility used by all other modules | 2-3 hrs |
| 3 | disk_module.py | HIGH | First forensic extraction capability | 4-5 hrs |
| 4 | log_module.py | HIGH | Parallel with disk_module | 3-4 hrs |
| 5 | ram_module.py | HIGH | Memory forensics integration | 5-6 hrs |
| 6 | Supabase Schema | HIGH | Database foundation (can start early) | 2-3 hrs |
| 7 | Flask API | MEDIUM | Connects modules to frontend | 3-4 hrs |
| 8 | React Dashboard | MEDIUM | Visualization layer | 4-5 hrs |
| 9 | Real-time Integration | MEDIUM | Live updates | 2-3 hrs |
| 10 | Report Generator | LOW | Final polish (optional for MVP) | 3-4 hrs |

---

## Critical Path (Minimum Viable Product - MVP)

To have a working forensic tool **as quickly as possible**, follow this path:

1. ✅ Phase 1: Environment Setup (FOUNDATION)
2. ✅ Phase 2: hasher.py (CORE UTILITY)
3. ✅ Phase 3.1: disk_module.py (FIRST FORENSIC OUTPUT)
4. ✅ Phase 3.2: log_module.py (SECOND FORENSIC OUTPUT)
5. ✅ Phase 6: Supabase Schema (DATABASE BACKBONE)
6. ✅ Phase 5.1: Flask API (CONNECT MODULES)
7. ✅ Phase 5.2: React Dashboard (SHOW RESULTS)
8. ⭐ **MVP READY: You can scan disks, parse logs, see results in UI**
9. Phase 4: ram_module.py (MEMORY FORENSICS - ADVANCED)
10. Phase 9: Real-time Integration (LIVE UPDATES - POLISH)
11. Phase 10: Report Generator (FINAL DELIVERABLE - OPTIONAL)

---

## Next Actions

1. **Verify Phase 1 completion** - Run `python -c "import pytsk3"` to confirm
2. **Start STEP 2** - Create `backend/hasher.py` with chunked hashing
3. **Setup Supabase project** - Create tables schema (can do in parallel)
4. **Start STEP 3 & 4** - Create disk_module.py and log_module.py with file signature database
5. **Test end-to-end** - Ensure modules integrate with Flask API

**Good luck building the forensic platform! 🔍**
