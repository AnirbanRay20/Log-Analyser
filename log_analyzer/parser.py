import re
from datetime import datetime

class LogParser:
    """
    Utility class to parse log files with a specific format:
    [YYYY-MM-DD HH:MM:SS] LEVEL Message [from IP X.X.X.X]
    """
    
    # Regex to match: [timestamp] LEVEL Message (with optional IP)
    LOG_PATTERN = r'\[(?P<timestamp>.*?)\]\s+(?P<level>INFO|WARNING|ERROR)\s+(?P<message>.*?)(?:\s+from IP\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?$'

    @staticmethod
    def parse_line(line):
        """
        Parses a single log line into a dictionary.
        """
        match = re.search(LogParser.LOG_PATTERN, line.strip())
        if match:
            data = match.groupdict()
            # Convert timestamp string to datetime object if needed for analysis
            try:
                data['datetime'] = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                data['datetime'] = None
            return data
        return None

    @staticmethod
    def parse_file(file_path):
        """
        Reads a file and returns a list of parsed log entries.
        """
        logs = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    parsed = LogParser.parse_line(line)
                    if parsed:
                        logs.append(parsed)
        except FileNotFoundError:
            print(f"Error: File {file_path} not found.")
        except Exception as e:
            print(f"An error occurred while reading the file: {e}")
            
        return logs
