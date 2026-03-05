import json
import csv
import os
import matplotlib.pyplot as plt
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)

class LogReporter:
    """
    Handles generation of reports in various formats.
    """
    
    def __init__(self, analysis_results, security_alerts):
        self.results = analysis_results
        self.alerts = security_alerts

    def generate_terminal_report(self):
        """
        Prints a formatted report to the terminal.
        """
        print(f"\n{Fore.CYAN}{Style.BRIGHT}===== SECURITY LOG ANALYSIS REPORT =====")
        print(f"{Fore.WHITE}Total Log Entries: {self.results['total_logs']}")
        
        print(f"\n{Fore.YELLOW}--- Log Levels ---")
        for level, count in self.results['level_counts'].items():
            print(f"{level}: {count}")

        print(f"\n{Fore.RED}--- Top Error Messages ---")
        for error, count in self.results['top_errors']:
            print(f"{error} ({count})")

        print(f"\n{Fore.MAGENTA}--- IP Statistics ---")
        print("Most Active IPs:")
        for ip, count in self.results['ip_stats']['top_ips']:
            print(f"  {ip}: {count}")

        print(f"\n{Fore.RED}{Style.BRIGHT}--- SECURITY ALERTS ---")
        
        # Brute Force Alerts
        for alert in self.alerts['brute_force_alerts']:
            print(f"{Fore.RED}[!] {alert['type']} from {alert['ip']} ({alert['attempts']} attempts)")
        
        # Scanning Alerts
        for alert in self.alerts['scanning_alerts']:
            print(f"{Fore.YELLOW}[!] {alert['type']} from {alert['ip']} ({alert['unique_errors']} unique endpoints)")

        # High Traffic Alerts
        for alert in self.alerts['traffic_alerts']:
            print(f"{Fore.RED}[!] {alert['type']} from {alert['ip']} ({alert['total_requests']} requests)")

        # Keyword Alerts (limit display to top 5)
        for alert in self.alerts['keyword_alerts'][:5]:
            print(f"{Fore.YELLOW}[!] {alert['type']}: '{alert['keyword']}' found")

    def export_text(self, filename='security_report.txt'):
        """
        Generates a plain text security report similar to the reference project.
        """
        with open(filename, 'w') as f:
            f.write("===== SECURITY ANALYSIS REPORT =====\n\n")
            f.write(f"Total Logs Analyzed: {self.results['total_logs']}\n")
            f.write("\n--- Log Level Distribution ---\n")
            for level, count in self.results['level_counts'].items():
                f.write(f"{level}: {count}\n")
            
            f.write("\n--- Top Active IPs ---\n")
            for ip, count in self.results['ip_stats']['top_ips']:
                f.write(f"{ip}: {count} requests\n")

            f.write("\n--- SECURITY ALERTS ---\n")
            if not any(self.alerts.values()):
                f.write("No suspicious activity detected.\n")
            else:
                for alert_list in self.alerts.values():
                    for alert in alert_list:
                        ip_info = f" from {alert['ip']}" if 'ip' in alert else ""
                        f.write(f"[!] {alert['type']}{ip_info}: {alert.get('details', '')}\n")

        print(f"{Fore.GREEN}Text report exported to {filename}")

    def export_json(self, filename='analysis_report.json'):
        """
        Exports the analysis and alerts to a JSON file.
        """
        data = {
            'statistics': self.results,
            'security_alerts': self.alerts
        }
        # Simplify the alerts for JSON export (avoid non-serializable objects)
        if 'keyword_alerts' in data['security_alerts']:
            for alert in data['security_alerts']['keyword_alerts']:
                if 'log' in alert and 'datetime' in alert['log']:
                    alert['log']['datetime'] = str(alert['log']['datetime'])
                    
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"\n{Fore.GREEN}JSON report exported to {filename}")

    def export_csv(self, filename='log_statistics.csv'):
        """
        Exports statistics to a CSV file.
        """
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Category', 'Item', 'Value'])
            
            # Log Levels
            for level, count in self.results['level_counts'].items():
                writer.writerow(['Log Level', level, count])
            
            # Top Errors
            for error, count in self.results['top_errors']:
                writer.writerow(['Top Error', error, count])
                
            # IP Stats
            for ip, count in self.results['ip_stats']['top_ips']:
                writer.writerow(['Active IP', ip, count])

        print(f"{Fore.GREEN}CSV report exported to {filename}")

    def generate_charts(self, output_dir='charts'):
        """
        Generates visualization charts using matplotlib.
        """
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # 1. Log Level Distribution
        levels = list(self.results['level_counts'].keys())
        counts = list(self.results['level_counts'].values())
        plt.figure(figsize=(10, 6))
        plt.pie(counts, labels=levels, autopct='%1.1f%%', startangle=140, colors=['#3498db', '#f39c12', '#e74c3c'])
        plt.title('Log Level Distribution')
        plt.savefig(os.path.join(output_dir, 'log_levels.png'))
        plt.close()

        # 2. Activity per Hour
        hours = sorted(self.results['hourly_activity'].keys())
        activity = [self.results['hourly_activity'][h] for h in hours]
        plt.figure(figsize=(10, 6))
        plt.bar(hours, activity, color='skyblue')
        plt.xlabel('Hour of the Day')
        plt.ylabel('Number of Logs')
        plt.title('Log Activity per Hour')
        plt.xticks(range(0, 24))
        plt.savefig(os.path.join(output_dir, 'hourly_activity.png'))
        plt.close()

        print(f"{Fore.GREEN}Charts generated in {output_dir}/ directory")
