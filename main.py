import argparse
import asyncio
from .scanner import run_scanner

def parse_arguments():
    parser = argparse.ArgumentParser(description='Mass stored XSS scanner')
    parser.add_argument('-u', '--url', help='Single URL/domain to test')
    parser.add_argument('-l', '--list', help='File containing list of URLs/domains to test')
    parser.add_argument('-p', '--payloads', help='File containing custom payloads')
    parser.add_argument('-o', '--output', help='File to save vulnerable URLs')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Timeout in seconds per request')
    parser.add_argument('-c', '--concurrency', type=int, default=15, help='Number of concurrent requests')
    parser.add_argument('-d', '--delay', type=float, default=1, help='Delay between requests in seconds')
    parser.add_argument('-r', '--retries', type=int, default=1, help='Number of retries for failed requests')
    parser.add_argument('--depth', type=int, default=0, help='Crawl depth (0 = current page only)')
    parser.add_argument('--max-pages', type=int, default=20, help='Maximum pages to crawl per domain')
    parser.add_argument('--verify-delay', type=int, default=3, help='Delay between injection and verification in seconds')
    return parser.parse_args()

if __name__ == '__main__':
    from .utils import log
    try:
        asyncio.run(run_scanner(parse_arguments()))
    except KeyboardInterrupt:
        print()
        log("Scan interrupted by user", "w")