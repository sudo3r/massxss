# massxss
Mass stored XSS scanner

## Installation
```shell
pip install -r requirements.txt
```

## Usage
```
usage: main.py [-h] [-u URL] [-l LIST] [-p PAYLOADS] [-o OUTPUT] [-t TIMEOUT] [-c CONCURRENCY] [-d DELAY] [-r RETRIES] [--depth DEPTH] [--max-pages MAX_PAGES] [--verify-delay VERIFY_DELAY]

options:
  -h, --help            show this help message and exit
  -u, --url URL         Single URL/domain to test
  -l, --list LIST       File containing list of URLs/domains to test
  -p, --payloads PAYLOADS
                        File containing custom payloads
  -o, --output OUTPUT   File to save vulnerable URLs
  -t, --timeout TIMEOUT
                        Timeout in seconds per request
  -c, --concurrency CONCURRENCY
                        Number of concurrent requests
  -d, --delay DELAY     Delay between requests in seconds
  -r, --retries RETRIES
                        Number of retries for failed requests
  --depth DEPTH         Crawl depth (0 = current page only)
  --max-pages MAX_PAGES
                        Maximum pages to crawl per domain
  --verify-delay VERIFY_DELAY
                        Delay between injection and verification in seconds
```