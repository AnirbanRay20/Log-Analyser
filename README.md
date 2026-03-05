# 🛡️ Python Log Analyzer & Suspicious Activity Detector

## 📌 Project Overview
This project is a **Python-based Log Analyzer tool** that reads a web server access log file (`access.log`) and detects suspicious activities such as:

- Brute Force login attempts
- Directory scanning attempts
- High traffic / bot-like activity

It also generates a detailed report (`security_report.txt`) containing the summary of log analysis.

---

## 🎯 Features
✅ Reads log file line by line  
✅ Extracts important fields (IP, method, URL, status code)  
✅ Counts total requests  
✅ Finds Top 5 IP addresses generating most requests  
✅ Finds Top 5 attacked/visited URLs  
✅ Detects suspicious IP activities:
- **Brute Force Attack Detection** (multiple 403 errors)
- **Scanning Detection** (multiple 404 errors)
- **High Traffic Detection** (possible bot/DDoS behavior)

✅ Generates output report automatically

---

## 🧠 Cybersecurity Use Cases
This tool can be used in:

- SOC (Security Operations Center) monitoring
- Incident response investigations
- Server security auditing
- Brute force and reconnaissance detection
- Website traffic and suspicious behavior monitoring

---

## 📂 Project Structure
Log_Analyzer_Project/
│
├── access.log
├── log_analyzer.py
└── security_report.txt


---

## 🛠️ Technologies Used
- Python 3
- File Handling
- Dictionaries
- Sorting & Data Analysis

---

## 📌 How It Works
The program reads each log entry, extracts:
- IP address
- Request method (GET/POST)
- Requested URL
- Status code (200, 403, 404, 500)

Then it performs frequency analysis to detect suspicious patterns.

---

## 🚨 Detection Rules Used
### 🔥 Brute Force Detection
If an IP has more than **5 occurrences of status code 403**, it is flagged as brute force attempt.

### 🔥 Scanning Detection
If an IP has more than **5 occurrences of status code 404**, it is flagged as scanning activity.

### 🔥 High Traffic Detection
If an IP makes more than **20 total requests**, it is flagged as possible bot/DDoS traffic.

---

## ▶️ How to Run
### Step 1: Update file paths inside the code
Edit in `log_analyzer.py`:

```python
file_path = "D:\\My Projects\\Log-Analyazer\\access.log"
report_path = "D:\\My Projects\\Log-Analyazer\\security_report.txt"

