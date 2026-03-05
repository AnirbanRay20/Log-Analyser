from collections import defaultdict
from datetime import timedelta

class SecurityDetector:
    """
    Detects potential security threats in log data.
    """
    
    # Keywords indicating suspicious activity
    SUSPICIOUS_KEYWORDS = [
        'unauthorized', 'failed', 'attack', 'breach', 
        'intrusion', 'exploit', 'sql injection', 'brute force'
    ]

    def __init__(self, logs):
        self.logs = logs

    def detect_suspicious_keywords(self):
        """
        Finds logs containing suspicious keywords.
        """
        alerts = []
        for log in self.logs:
            message_lower = log['message'].lower()
            for kw in self.SUSPICIOUS_KEYWORDS:
                if kw in message_lower:
                    alerts.append({
                        'type': 'Suspicious Keyword',
                        'keyword': kw,
                        'log': log
                    })
                    break
        return alerts

    def detect_brute_force(self, threshold=5, time_window_seconds=300):
        """
        Detects possible brute force attacks.
        Logic: Multiple failed login attempts from the same IP within a short period.
        """
        failed_attempts = defaultdict(list)
        alerts = []
        
        # Filter for failed login attempts with IP addresses
        for log in self.logs:
            msg = log['message'].lower()
            if ('failed' in msg or '403 forbidden' in msg) and log.get('ip'):
                dt = log.get('datetime')
                if dt:
                    failed_attempts[log['ip']].append(dt)
        
        # Analyze attempts per IP
        for ip, timestamps in failed_attempts.items():
            timestamps.sort()
            for i in range(len(timestamps) - threshold + 1):
                if timestamps[i + threshold - 1] - timestamps[i] <= timedelta(seconds=time_window_seconds):
                    alerts.append({
                        'type': 'Possible Brute Force Attack',
                        'ip': ip,
                        'attempts': len(timestamps),
                        'details': f"Multiple forbidden/failed attempts detected"
                    })
                    break
                    
        return alerts

    def detect_scanning(self, threshold=5):
        """
        Detects vulnerability scanning or directory bursting.
        Logic: Many unique 404 Not Found errors from a single IP.
        """
        scanning_ips = defaultdict(set)
        alerts = []
        
        for log in self.logs:
            if '404 not found' in log['message'].lower() and log.get('ip'):
                scanning_ips[log['ip']].add(log['message'])
        
        for ip, unique_messages in scanning_ips.items():
            if len(unique_messages) >= threshold:
                alerts.append({
                    'type': 'Vulnerability Scanning Detected',
                    'ip': ip,
                    'unique_errors': len(unique_messages),
                    'details': f"Accessing multiple non-existent endpoints"
                })
        
        return alerts

    def detect_high_traffic(self, threshold=20):
        """
        Detects potential DDoS or automated bot activity.
        Logic: Total requests from an IP exceeds a safety threshold.
        """
        ip_counts = defaultdict(int)
        alerts = []
        
        for log in self.logs:
            if log.get('ip'):
                ip_counts[log['ip']] += 1
        
        for ip, count in ip_counts.items():
            if count >= threshold:
                alerts.append({
                    'type': 'High Traffic / Suspicious Activity',
                    'ip': ip,
                    'total_requests': count,
                    'details': f"Exceeded threshold of {threshold} requests"
                })
        
        return alerts

    def get_all_security_alerts(self):
        """
        Returns a combined list of all detected security alerts.
        """
        return {
            'keyword_alerts': self.detect_suspicious_keywords(),
            'brute_force_alerts': self.detect_brute_force(),
            'scanning_alerts': self.detect_scanning(),
            'traffic_alerts': self.detect_high_traffic(),
            'pattern_alerts': self.detect_attack_patterns()
        }
