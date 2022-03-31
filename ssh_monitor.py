import sys
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, FileSystemEventHandler
import re
import datetime
import requests
import json

dir_path = "/Users/yuandarong/mycode/fail2ban_ssh/"
ssh_log_path = "/Users/yuandarong/mycode/fail2ban_ssh/ssh.log"
api_add_entry = "http://127.0.0.1:8080/api/entries/add/{}"

def pad_day_str(day_str):
    if len(day_str) == 1:
        day_str = '0' + day_str
    return day_str
        
def parse_failed_line(log_line):
    timestamp = ''
    log_items = log_line.split()
    mon_str, day_str, time_str = log_items[:3]
    ip = log_items[-4]
    day_str = pad_day_str(day_str)
    date_str = ' '.join([mon_str, day_str, time_str])
    date_obj = datetime.datetime.strptime(date_str, '%b %d %X')
    date_obj = date_obj.replace(year=datetime.datetime.now().year)
    timestamp = int(datetime.datetime.timestamp(date_obj))
    return timestamp, ip

def add_attempt_entry(timestamp, ip):
    payload = json.dumps({
        'source': ip,
        'service': 'ssh',
        'timestamp': timestamp
    })
    api = api_add_entry.format(ip)
    r = requests.put(api, data=payload)
    print(r)
    print(r.content)

class SSHLogFileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == ssh_log_path and event.event_type == 'modified':
            with open(ssh_log_path, 'r') as ssh_log:
                log_lines = ssh_log.readlines()
                for log_line in log_lines:
                    if "Failed password" in log_line:
                        print(log_line)
                        timestamp, ip = parse_failed_line(log_line)
                        add_attempt_entry(timestamp, ip)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    event_handler = SSHLogFileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, dir_path, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()
