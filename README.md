# massxss
Mass XSS Exploitation

## Installation
```shell
pip install -r requirements.txt
```

## Usage
```
usage: massxss.py [-h] -t TARGETS -p PAYLOADS [-c CONCURRENCY] [-to TIMEOUT]

Mass XSS Exploitation

options:
  -h, --help            show this help message and exit
  -t, --targets TARGETS
                        File containing target URLs
  -p, --payloads PAYLOADS
                        File containing XSS payloads
  -c, --concurrency CONCURRENCY
                        Concurrent requests (default: 30)
  -to, --timeout TIMEOUT
                        Request timeout in seconds (default: 20)
```
