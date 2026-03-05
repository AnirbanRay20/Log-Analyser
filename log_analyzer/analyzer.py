from collections import Counter
from datetime import datetime

class LogAnalyzer:
    """
    Analyzes logs and generates statistics.
    """
    
    def __init__(self, logs):
        self.logs = logs

    def get_log_level_counts(self):
        """
        Returns a dictionary with counts of INFO, WARNING, and ERROR logs.
        """
        levels = [log['level'] for log in self.logs]
        return dict(Counter(levels))

    def get_top_errors(self, top_n=5):
        """
        Returns the top N most frequent error messages.
        """
        errors = [log['message'] for log in self.logs if log['level'] == 'ERROR']
        return Counter(errors).most_common(top_n)

    def get_hourly_activity(self):
        """
        Returns log frequency per hour of the day.
        """
        hours = []
        for log in self.logs:
            dt = log.get('datetime')
            if dt:
                hours.append(dt.hour)
            else:
                # Fallback to string if datetime conversion failed
                try:
                    hour_str = log['timestamp'].split(' ')[1].split(':')[0]
                    hours.append(int(hour_str))
                except:
                    pass
        
        return dict(Counter(hours))

    def get_ip_statistics(self):
        """
        Returns top active IPs and IPs with failed login attempts.
        """
        ips = [log['ip'] for log in self.logs if log.get('ip')]
        top_ips = Counter(ips).most_common(5)
        
        failed_ips = [log['ip'] for log in self.logs if 'failed' in log['message'].lower() and log.get('ip')]
        top_failed_ips = Counter(failed_ips).most_common(5)
        
        return {
            'top_ips': top_ips,
            'failed_login_ips': top_failed_ips
        }

    def get_summary(self):
        """
        Returns a comprehensive summary of analysis.
        """
        return {
            'total_logs': len(self.logs),
            'level_counts': self.get_log_level_counts(),
            'top_errors': self.get_top_errors(),
            'hourly_activity': self.get_hourly_activity(),
            'ip_stats': self.get_ip_statistics()
        }
