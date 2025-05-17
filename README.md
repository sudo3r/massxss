# massxss
Mass XSS Exploitation

## Installation
```shell
pip install -r requirements.txt
```

## Usage
```
usage: massxss.py [-h] -t TARGET -p PAYLOADS [-o OUTPUT] [-c CONCURRENCY] [-T TIMEOUT] [-d DELAY]

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   File containing target URLs or domains
  -p, --payloads PAYLOADS
                        File containing XSS payloads
  -o, --output OUTPUT   Output file for results (JSON format)
  -c, --concurrency CONCURRENCY
                        Number of concurrent requests (default: 5)
  -T, --timeout TIMEOUT
                        Request timeout in seconds (default: 30)
  -d, --delay DELAY     Delay before checking stored payload (default: 5)

```
