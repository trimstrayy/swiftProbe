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

## Initialization Instructions For AI Collaborator

Use the following steps to initialize the project structure:

1. Create the top-level directories `backend`, `frontend`, and `evidence`.
2. Inside `backend`, initialize a Flask application in `app.py`.
3. Create a `modules` directory under `backend` and add empty classes for `DiskModule`, `RAMModule`, and `LogModule`.
4. Set up `backend/core/supabase_db.py` to initialize the Supabase client using environment variables.
5. Inside `frontend`, initialize a Vite + React project and install Tailwind CSS.
6. Generate `backend/requirements.txt` with the backend dependencies: `flask`, `supabase`, `pytsk3`, and `volatility3`.