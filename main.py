import argparse
import sys
from log_analyzer.parser import LogParser
from log_analyzer.analyzer import LogAnalyzer
from log_analyzer.security_detector import SecurityDetector
from log_analyzer.report import LogReporter

def main():
    parser = argparse.ArgumentParser(description="Security Log Analyzer - Cybersecurity Monitoring Tool")
    
    # File Arguments
    parser.add_argument('--file', type=str, required=True, help="Path to the log file to analyze")
    
    # Filtering Arguments
    parser.add_argument('--level', type=str, choices=['INFO', 'WARNING', 'ERROR'], help="Filter logs by level")
    parser.add_argument('--keyword', type=str, help="Search for a specific keyword in logs")
    parser.add_argument('--ip', type=str, help="Filter logs by a specific IP address")
    
    # Export Arguments
    parser.add_argument('--export', type=str, choices=['json', 'csv', 'txt', 'all'], help="Export report to specific format")
    parser.add_argument('--charts', action='store_true', help="Generate visualization charts")

    args = parser.parse_args()

    # 1. Parse logs
    logs = LogParser.parse_file(args.file)
    if not logs:
        print("No valid logs found to analyze.")
        sys.exit(0)

    # 2. Apply Filters if specified
    filtered_logs = logs
    if args.level:
        filtered_logs = [log for log in filtered_logs if log['level'] == args.level]
    if args.keyword:
        filtered_logs = [log for log in filtered_logs if args.keyword.lower() in log['message'].lower()]
    if args.ip:
        filtered_logs = [log for log in filtered_logs if log.get('ip') == args.ip]

    if not filtered_logs:
        print("No logs match the specified filters.")
        sys.exit(0)

    # 3. Analyze filtered logs
    analyzer = LogAnalyzer(filtered_logs)
    analysis_results = analyzer.get_summary()

    # 4. Detect security threats (using ALL logs for context, but can be filtered too)
    detector = SecurityDetector(logs)
    security_alerts = detector.get_all_security_alerts()

    # 5. Generate Reports
    reporter = LogReporter(analysis_results, security_alerts)
    
    reporter.generate_terminal_report()

    if args.export == 'json' or args.export == 'all':
        reporter.export_json()
    if args.export == 'csv' or args.export == 'all':
        reporter.export_csv()
    if args.export == 'txt' or args.export == 'all':
        reporter.export_text()
    if args.charts:
        reporter.generate_charts()

if __name__ == "__main__":
    main()
