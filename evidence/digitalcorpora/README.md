Digital Corpora evidence intake guide for SwiftProbe.

This guide is still useful after the evidence cleanup: it documents how to stage local datasets without checking them into git and how to verify them with the current scripts.

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

Repository update note:
- The bundled reference evidence was removed from git history.
- Any new evidence should stay in ignored local folders only.
- The main README now points to the NIST CFReDS File Carving archive as the source of the pre-existing sample evidence.

Quick verify command (project root):
PowerShell: .\scripts\phase1_verify.ps1