# 🛡️ Security Log Analyzer

A Python-based command-line tool and interactive dashboard for parsing, analyzing, and detecting security threats in system log files. This project is designed for security monitoring, threat detection, and debugging.

## 🚀 Features

- **Log Parsing**: Extract timestamp, log level, message, and IP address using regex.
- **Filtering**: Filter logs by level (INFO, WARNING, ERROR), keywords, or IP addresses.
- **Statistics**: Generate reports on log level distribution, hourly activity, and most active IPs.
- **Security Detection**:
  - **Suspicious Keyword Detection**: Detect words such as "unauthorized", "failed", "breach", "exploit", etc.
  - **Brute Force Detection**: Flags IPs with more than 5 failed login attempts within a short time window.
  - **Attack Pattern Detection**: Identifies repeated authentication failures and suspicious traffic bursts.
- **Reporting**:
  - **Terminal Report**: Colored output for quick analysis.
  - **JSON Export**: Detailed structured results for integration.
  - **CSV Export**: Statistics for spreadsheet analysis.
  - **Visualizations**: PNG charts for log levels and hourly activity.
- **Web Dashboard**: Interactive Streamlit UI for monitoring and alerts.

## 📁 Project Structure

```text
log_analyzer/
├── main.py                # CLI entry point
├── parser.py              # Log parsing logic
├── analyzer.py            # Statistical analysis
├── security_detector.py   # Threat detection logic
├── report.py              # Multi-format reporting
├── dashboard.py           # Streamlit dashboard
├── sample_logs.log        # Sample test data
└── README.md              # Documentation
```

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/AnirbanRay20/Log-Analyser.git
   cd Log-Analyser
   ```

2. **Install dependencies**:
   ```bash
   pip install colorama matplotlib streamlit plotly pandas
   ```

## 📖 Usage

### Command Line Interface (CLI)

Run the basic analysis:
```bash
python main.py --file log_analyzer/sample_logs.log
```

Filter by level and keyword:
```bash
python main.py --file log_analyzer/sample_logs.log --level ERROR --keyword "failed"
```

Export results and generate charts:
```bash
python main.py --file log_analyzer/sample_logs.log --export all --charts
```

### Web Dashboard

Launch the interactive dashboard:
```bash
streamlit run dashboard.py
```

## 🛡️ Security Detection Logic

- **Brute Force**: The `SecurityDetector` tracks failed login attempts per IP. If the count exceeds 5 within a 5-minute window, it triggers a "Possible Brute Force Attack" alert.
- **Keywords**: A pre-defined list of suspicious keywords is checked against every log message. Matches are logged as security alerts.
- **Patterns**: The system monitors for repeated 'authentication failure' messages globally and specific 'burst' keywords.

## 📊 Sample Output

- **analysis_report.json**: Complete results including all alerts.
- **log_statistics.csv**: Tabular statistics.
- **charts/**: Visualization output (`log_levels.png`, `hourly_activity.png`).

## 📜 License

This project is licensed under the MIT License.
