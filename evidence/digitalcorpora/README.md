Digital Corpora evidence intake guide for SwiftProbe.

Folder mapping:
- raw_images: place disk images such as .raw, .dd, .img, .E01
- memory_dumps: place memory captures such as .raw, .mem, .dmp
- evtx_logs: place Windows event logs such as .evtx
- downloads: keep original archive downloads (.zip, .7z) before extraction
- notes: keep dataset source URLs, checksums, and provenance notes

Recommended workflow:
1. Download datasets from https://digitalcorpora.org
2. Save archives in downloads
3. Extract files into raw_images, memory_dumps, and evtx_logs as appropriate
4. Record source URL and SHA-256 in notes
5. Do not commit large evidence binaries to git

Quick verify command (project root):
PowerShell: .\scripts\phase1_verify.ps1