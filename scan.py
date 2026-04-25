#!/usr/bin/env python3
import requests
import urllib3
import re
import random
import argparse
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init
from tqdm import tqdm

# Inisialisasi Colorama & Sembunyikan Warning SSL
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- STEALTH CONFIGURATION ---
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'wp-cli/2.9.0'
]

def get_stealth_headers():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'X-Forwarded-For': '127.0.0.1',
        'X-Real-IP': '127.0.0.1'
    }

# --- CORE LOGIC ---
def scan_target(url):
    url = url.strip()
    if not url: return None
    
    clean_url = url.replace('http://', '').replace('https://', '').rstrip('/')
    protocols = ['https://', 'http://']
    
    for proto in protocols:
        try:
            target_url = proto + clean_url
            headers = get_stealth_headers()

            # PATH: Contact Form by Supsystic
            readme_path = f"{target_url}/wp-content/plugins/contact-form-by-supsystic/readme.txt"
            
            r = requests.get(readme_path, headers=headers, timeout=10, verify=False)
            
            # --- STRICT DETECTION ---
            # Pengecekan spesifik memastikan ini adalah plugin 'Contact Form by Supsystic'
            if r.status_code == 200 and "contact form by supsystic" in r.text.lower():
                
                # Ekstraksi versi
                match = re.search(r'(?:Stable tag:|Version:)\s*([\d.]+)', r.text)
                if match:
                    version_str = match.group(1)
                    try:
                        v_parts = [int(x) for x in version_str.split('.') if x.isdigit()]
                        
                        is_vuln = False
                        # LOGIC: 1.7.36 kebawah = VULN (Termasuk 1.7.36)
                        if len(v_parts) >= 3:
                            if v_parts[0] < 1:
                                is_vuln = True
                            elif v_parts[0] == 1:
                                if v_parts[1] < 7:
                                    is_vuln = True
                                elif v_parts[1] == 7:
                                    # <= 36 artinya 1.7.36 masuk kategori VULN
                                    if v_parts[2] <= 36:
                                        is_vuln = True
                        elif len(v_parts) == 2:
                            if v_parts[0] < 1 or (v_parts[0] == 1 and v_parts[1] < 7):
                                is_vuln = True

                        if is_vuln:
                            with open('vulnerable_supsystic.txt', 'a') as f:
                                f.write(f"{target_url}\n")
                            return f"{Fore.GREEN}[VULN] {target_url} | v{version_str}"
                        else:
                            return f"{Fore.YELLOW}[SAFE] {target_url} | v{version_str}"
                    
                    except:
                        pass
                
                # Jika status 200 tapi pola versi tidak ditemukan
                return None

        except requests.exceptions.RequestException:
            continue
            
    return None

# --- MAIN RUNNER ---
def main():
    parser = argparse.ArgumentParser(description="WP SUPSYSTIC CONTACT FORM MASS SCAN")
    parser.add_argument("-l", "--list", help="Path ke file list target", required=True)
    parser.add_argument("-t", "--threads", help="Jumlah threads", type=int, default=30)
    args = parser.parse_args()

    print(f"\n{Fore.CYAN}=============================================")
    print(f"{Fore.CYAN}   SUPSYSTIC CONTACT FORM MASS SCAN")
    print(f"{Fore.CYAN}=============================================")
    print(f"{Fore.WHITE}Target List : {args.list}")
    print(f"{Fore.WHITE}Threads     : {args.threads}")
    print(f"{Fore.CYAN}---------------------------------------------\n")

    if not os.path.exists(args.list):
        print(f"{Fore.RED}Error: File '{args.list}' tidak ditemukan!")
        return

    try:
        with open(args.list, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_target, url): url for url in targets}
            
            with tqdm(total=len(targets), desc="Scanning", unit="url", bar_format="{l_bar}{bar:25}{r_bar}") as pbar:
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        tqdm.write(res)
                    pbar.update(1)

        print(f"\n{Fore.CYAN}Selesai! List VULN: vulnerable_supsystic.txt")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Dibatalkan oleh user")

if __name__ == "__main__":
    main()
