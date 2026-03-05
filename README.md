# 🛡️ Python Log Analyzer & Suspicious Activity Detector

Small, efficient script to parse a web server `access.log`, summarize traffic,
and detect suspicious activity (brute force, scanning, high traffic).

**What's changed**
- Replaced brittle space-splitting with a regex-based parser.
- Uses `collections.Counter` for fast counting.
- Configurable constants for thresholds and top-N results.
- Safer file handling and clearer output paths.

**Default files**
- Input log: `access.log`
- Output report: `security_report.txt`

**Detection thresholds (in code)**
- Brute force: `BRUTE_FORCE_THRESHOLD = 5`
- Scanning: `SCANNING_THRESHOLD = 5`
- High traffic: `HIGH_TRAFFIC_THRESHOLD = 20`

## Features
- Parses IP, method, URL, and status code via regex.
- Counts total requests and top IPs/URLs.
- Flags suspicious IPs by the thresholds above.
- Generates a human-readable report file.

## How to Run
1. Place your `access.log` in the same folder (or modify `FILE_PATH` in the script).
2. Run:

```powershell
python log_analyazer.py
```

The script writes `security_report.txt` in the same folder.

## Next steps (optional)
- Add a CLI to override `FILE_PATH` / `REPORT_PATH` and thresholds.
- Add unit tests for the regex parser and report generation.

---
Updated to reflect the refactored implementation in `log_analyazer.py`.
├── log_analyzer.py

