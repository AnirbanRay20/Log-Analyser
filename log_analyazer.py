import re
from collections import Counter

FILE_PATH = "access.log"
REPORT_PATH = "security_report.txt"
BRUTE_FORCE_THRESHOLD = 5
SCANNING_THRESHOLD = 5
HIGH_TRAFFIC_THRESHOLD = 20
TOP_N = 5

LOG_RE = re.compile(r'(?P<ip>\S+) .* \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) [^"]*" (?P<status>\d{3})')

ip_counter = Counter()
status_counter = Counter()
url_counter = Counter()
ip_403 = Counter()
ip_404 = Counter()
total_requests = 0

try:
    with open(FILE_PATH, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = LOG_RE.match(line)
            if not m:
                continue
            total_requests += 1
            ip = m.group("ip")
            url = m.group("url")
            status = m.group("status")

            ip_counter[ip] += 1
            status_counter[status] += 1
            url_counter[url] += 1

            if status == "403":
                ip_403[ip] += 1
            elif status == "404":
                ip_404[ip] += 1
except FileNotFoundError:
    print(f"Log file not found: {FILE_PATH}")
    raise SystemExit(1)

top_ips = ip_counter.most_common(TOP_N)
top_urls = url_counter.most_common(TOP_N)

suspicious = []
for ip, cnt in ip_counter.items():
    if cnt > HIGH_TRAFFIC_THRESHOLD:
        suspicious.append(f"[HIGH TRAFFIC] {ip} -> {cnt} requests")
for ip, cnt in ip_403.items():
    if cnt > BRUTE_FORCE_THRESHOLD:
        suspicious.append(f"[BRUTE FORCE] {ip} -> {cnt} failed logins (403)")
for ip, cnt in ip_404.items():
    if cnt > SCANNING_THRESHOLD:
        suspicious.append(f"[SCANNING] {ip} -> {cnt} not found requests (404)")

with open(REPORT_PATH, "w", encoding="utf-8") as report:
    report.write("=========== SECURITY LOG REPORT ===========\n\n")
    report.write(f"Total Requests: {total_requests}\n\n")

    report.write("------ STATUS CODE SUMMARY ------\n")
    for status, cnt in sorted(status_counter.items(), key=lambda x: int(x[0]) if x[0].isdigit() else x[0]):
        report.write(f"{status} -> {cnt}\n")
    report.write("\n")

    report.write("------ TOP IP ADDRESSES ------\n")
    for i, (ip, cnt) in enumerate(top_ips, 1):
        report.write(f"{i}. {ip} -> {cnt} requests\n")
    report.write("\n")

    report.write("------ TOP URLS ------\n")
    for i, (url, cnt) in enumerate(top_urls, 1):
        report.write(f"{i}. {url} -> {cnt} hits\n")
    report.write("\n")

    report.write("------ SUSPICIOUS ACTIVITY ------\n")
    if not suspicious:
        report.write("No suspicious activity detected.\n")
    else:
        for alert in suspicious:
            report.write(alert + "\n")

    report.write("\n=========== END OF REPORT ===========\n")

print("✅ Log Analysis Completed Successfully!")
print("📄 Report Generated:", REPORT_PATH)

