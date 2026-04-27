README.md
# SwiftProbe

**Modular digital forensics and triage toolkit**

SwiftProbe is a digital investigation platform designed to reconstruct incidents through bit-for-bit disk analysis, volatile memory extraction, and system log correlation. It follows a "Forensics-as-a-Service" model, where local Python-based analysis engines push validated forensic artifacts to a centralized Supabase backend for real-time collaboration and report generation.

## At A Glance

| Area | Stack |
| --- | --- |
| Language | Python 3.10+ |
| Backend | Flask |
| Database | Supabase (PostgreSQL) |
| Frontend | React (Vite) with Tailwind CSS |
| Core Libraries | pytsk3, Volatility 3, python-evtx, ReportLab |
| Authentication | Supabase Auth |

## Host Prerequisites

To develop and execute SwiftProbe, install the following software and drivers on the host machine. These tools provide the required environment for low-level binary analysis and cloud synchronization.

### 1. Core Runtime Environments

- Python 3.10.x or higher: Primary runtime for forensic modules. During installation, enable `Add to PATH`.
- Node.js (LTS): Required for the React + Vite frontend development server and npm package management.

### 2. Forensic System Dependencies

SwiftProbe interacts with raw disk images and memory structures, so these system-level dependencies are required:

- The Sleuth Kit (TSK): Required by `pytsk3`. On Windows, install compiled binaries so Python can interface with NTFS/FAT file systems.
- Microsoft Visual C++ Build Tools: Required on Windows to compile forensic library extensions during `pip install`.
- Git: Required for version control and modular team development workflows.

### 3. Database and API Tools

- Supabase CLI (optional): Useful for managing local database migrations and edge functions.
- Postman or Insomnia: Recommended for testing Flask API endpoints before React frontend integration.

### 4. Recommended Development Environment

- Visual Studio Code (VS Code) with the following extensions:
	- Python (Microsoft)
	- ES7+ React/Redux/React-Native snippets
	- Tailwind CSS IntelliSense
	- Thunder Client (API testing)

## System Architecture

SwiftProbe isolates forensic logic into independent modules that communicate with a central database. That keeps disk analysis, memory analysis, and log parsing parallelized without data overlap.

```text
swiftprobe/
├── backend/
│   ├── app.py              # Flask entry point and API routes
│   ├── .env                # Supabase credentials and API keys
│   ├── core/
│   │   ├── hasher.py       # SHA-256 integrity and chain of custody logic
│   │   └── supabase_db.py  # Supabase client and database session management
│   ├── modules/
│   │   ├── disk_module.py  # Disk carving and file system analysis (pytsk3)
│   │   ├── ram_module.py   # Volatile memory analysis (Volatility 3)
│   │   └── log_module.py   # Event log parsing and timeline mining
│   ├── reports/
│   │   └── generator.py    # ReportLab PDF generation logic
│   └── requirements.txt    # Python dependencies
│
├── frontend/
│   ├── src/
│   │   ├── components/     # Reusable UI elements (artifact tables, charts)
│   │   ├── pages/          # Dashboard, evidence browser, settings
│   │   ├── hooks/          # Real-time Supabase data fetching hooks
│   │   ├── services/       # API calling logic
│   │   └── App.jsx
│   ├── tailwind.config.js
│   ├── index.html
│   └── package.json
│
├── evidence/               # Directory for local mounting of raw images
└── README.md
```

## Core Capabilities

- Evidence ingestion: mount and read Raw/E01 disk images in a read-only state.
- File carving: recover deleted assets from unallocated space using file signature headers.
- Memory forensics: extract active network connections and process trees from RAM dumps.
- Timeline correlation: build a unified chronological sequence of events from MFT and system logs.
- Reporting: generate cryptographically validated PDF reports of all findings.
