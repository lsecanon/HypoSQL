Absolutely — here's the full updated sqlifinder.py script with the following new features:

-a / --advanced to load all payloads from sql-injection-payload-list/Intruder/**/*.txt

-v / --verbose to print every payload tried

Cleaned up, efficient, and organized



---

import requests
import re
import argparse
import os
import sys
import time
from huepy import *
from core import requester, extractor, crawler
from urllib.parse import unquote
from tqdm import tqdm
import glob

start_time = time.time()

def clear():
    os.system('cls' if 'win' in sys.platform else 'clear')

def banner():
    print(green('''
        ___ ____         __          
       ___ ___ _/ (_) _(_)__  ___/ /__ ____  
      (_-</ _ `/ / / _/ / _ \/ _  / -_) __/ 
     /___/\_, /_/_/_//_/_//_/\_,_/\__/_/    
         /_/        

        ~ by @americo        v1.0
    '''))

def concatenate_list_data(data_list):
    return "\n".join(str(el) for el in data_list)

def parse_boolean(value):
    return str(value).lower() in ['true', '1', 'yes']

def load_advanced_payloads():
    payloads = []
    base_dir = os.path.join(os.path.dirname(__file__), 'sql-injection-payload-list', 'Intruder')
    for file_path in glob.glob(f"{base_dir}/**/*.txt", recursive=True):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                payloads.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(red(f"[-] Failed to read {file_path}: {e}"))
    return payloads

def main():
    parser = argparse.ArgumentParser(description='sqlifinder - a SQL injection scanner tool')
    parser.add_argument('-d', '--domain', help='Domain name of the target [ex. example.com]', required=True)
    parser.add_argument('-s', '--subs', help='Include subdomains [ex: --subs True]', type=parse_boolean, default=False)
    parser.add_argument('-a', '--advanced', help='Use advanced payloads from directory', action='store_true')
    parser.add_argument('-v', '--verbose', help='Verbose output (shows every payload tried)', action='store_true')
    args = parser.parse_args()

    archive_url = (
        f"http://web.archive.org/cdx/search/cdx?url=*.{args.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
        if args.subs else
        f"http://web.archive.org/cdx/search/cdx?url={args.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
    )

    clear()
    banner()

    print(blue("[+] Fetching archived URLs..."))
    response = requester.connector(archive_url)

    print(blue("[+] Crawling live URLs..."))
    crawled_urls = crawler.spider(f"http://{args.domain}", 10)

    response += "\n" + concatenate_list_data(crawled_urls)
    if not response:
        print(red("[-] No URLs found to scan."))
        return

    response = unquote(response)

    print(f"\n[{blue('INF')}] Scanning SQL injection for {args.domain}")

    exclude = ['woff', 'js', 'ttf', 'otf', 'eot', 'svg', 'png', 'jpg']
    final_uris = extractor.param_extract(response, "high", exclude, "")

    # Load payloads
    payloads = []

    if args.advanced:
        print(blue("[+] Loading advanced payloads..."))
        payloads = load_advanced_payloads()
    else:
        if not os.path.exists('payloads.txt'):
            print(red("[-] 'payloads.txt' file not found."))
            return
        with open('payloads.txt', 'r') as file:
            payloads = file.read().splitlines()

    if not payloads:
        print(red("[-] No payloads loaded."))
        return

    # Start scanning
    for uri in final_uris:
        for payload in payloads:
            final_url = uri + payload
            if args.verbose:
                print(f"{cyan('[DEBUG]')} Trying: {final_url}")
            try:
                req = requests.get(final_url, timeout=10)
                if any(keyword in req.text for keyword in ['SQL', 'sql', 'Sql']):
                    print(f"[{green('sql-injection')}] {final_url}")
                    break
            except requests.exceptions.RequestException:
                continue

if __name__ == "__main__":
    clear()
    banner()
    main()


---

Let me know if you want to:

Log found URLs to a file

Add threading or async support for faster scanning

Auto-detect WAF/blocking behavior

Color matches by source (archive vs crawler)


Happy to extend it however you want.

