import asyncio
import aiohttp
import os
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from collections import deque

from utils import (
    DEFAULT_PAYLOADS, VERIFICATION_PATTERNS, get_random_user_agent, log
)

def verify_xss(content, payload):
    for pattern in VERIFICATION_PATTERNS:
        if pattern.search(content):
            return True
    if payload.lower() in content.lower():
        if any(context in content.lower() for context in ['<script>', 'onload=', 'onerror=', 'javascript:']):
            return True
    return False

async def check_website_status(session, url):
    try:
        async with session.head(url, allow_redirects=True, ssl=False) as response:
            return response.status == 200
    except Exception as e:
        log(f"Connection error for {url}: {str(e)}", "w")
        return False

async def fetch_with_retry(session, url, retries, delay):
    for attempt in range(retries + 1):
        try:
            async with session.get(url, allow_redirects=True, ssl=False) as response:
                if response.status == 200:
                    content = await response.text()
                    if not content.strip():
                        log(f"Empty response from {url}", "w")
                        return None
                    return content
                log(f"HTTP {response.status} for {url} (attempt {attempt+1}/{retries+1})", "w")
        except Exception as e:
            log(f"Error fetching {url}: {str(e)} (attempt {attempt+1}/{retries+1})", "w")
        if attempt < retries:
            await asyncio.sleep(delay * (attempt + 1))
    log(f"Failed to fetch {url} after {retries + 1} attempts", "e")
    return None

async def submit_form(session, form_url, form_data, method):
    try:
        if method == 'post':
            async with session.post(form_url, data=form_data, ssl=False) as response:
                return await response.text()
        else:
            async with session.get(form_url, params=form_data, ssl=False) as response:
                return await response.text()
    except Exception as e:
        log(f"Error submitting form to {form_url}: {str(e)}", "w")
        return None

async def test_stored_xss(session, form_url, form_details, payload, verify_delay):
    form_data = {}
    for input_field in form_details['inputs']:
        if input_field['type'] in ['hidden', 'submit']:
            form_data[input_field['name']] = input_field.get('value', '')
        else:
            form_data[input_field['name']] = payload
    submission_response = await submit_form(session, form_url, form_data, form_details['method'])
    if not submission_response:
        return False
    await asyncio.sleep(verify_delay)
    verification_url = form_details.get('verification_url', form_url)
    verification_response = await fetch_with_retry(session, verification_url, 1, 1)
    if not verification_response:
        return False
    return verify_xss(verification_response, payload)

async def process_form(session, semaphore, form_url, form_details, payloads, output_file, delay, verify_delay):
    async with semaphore:
        log(f"Testing form at {form_url}", "i")
        for payload in payloads:
            try:
                is_vulnerable = await test_stored_xss(
                    session, form_url, form_details, payload, verify_delay
                )
                if is_vulnerable:
                    log(f"Vulnerable: {form_url} - Payload: {payload}", "s")
                    if output_file:
                        with open(output_file, 'a') as f:
                            f.write(f"{form_url} - Payload: {payload}\n")
                    return True
            except Exception as e:
                log(f"Error testing payload on {form_url}: {str(e)}", "w")
            await asyncio.sleep(delay)
        log(f"No stored XSS found at {form_url}", "i")
        return False

async def crawl_website(session, semaphore, start_url, payloads, output_file, delay, retries, depth, max_pages, verify_delay):
    domain = urlparse(start_url).netloc
    visited = set()
    queue = deque([(start_url, 0)])
    vulnerable = 0
    errors = 0
    pages_crawled = 0
    while queue and pages_crawled < max_pages:
        url, current_depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        if not await check_website_status(session, url):
            log(f"Skipping {url} - Site not reachable", "w")
            errors += 1
            continue
        log(f"Crawling {url} (depth {current_depth})", "i")
        html = await fetch_with_retry(session, url, retries, delay)
        if not html:
            errors += 1
            continue
        try:
            soup = BeautifulSoup(html, 'html.parser')
            pages_crawled += 1
        except Exception as e:
            log(f"Error parsing HTML from {url}: {str(e)}", "w")
            errors += 1
            continue
        forms = soup.find_all('form')
        if forms:
            log(f"Found {len(forms)} forms at {url}", "i")
            tasks = []
            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').lower()
                form_url = urljoin(url, action) if action else url
                inputs = []
                for input_tag in form.find_all('input'):
                    inputs.append({
                        'type': input_tag.get('type', 'text'),
                        'name': input_tag.get('name'),
                        'value': input_tag.get('value', '')
                    })
                for textarea in form.find_all('textarea'):
                    inputs.append({
                        'type': 'textarea',
                        'name': textarea.get('name'),
                        'value': textarea.get('value', '')
                    })
                form_details = {
                    'action': form_url,
                    'method': method,
                    'inputs': inputs,
                    'verification_url': url
                }
                tasks.append(process_form(
                    session, semaphore, form_url, form_details,
                    payloads, output_file, delay, verify_delay
                ))
            results = await asyncio.gather(*tasks)
            vulnerable += sum(results)
        if current_depth < depth:
            links = set()
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                    continue
                absolute_url = urljoin(url, href)
                parsed = urlparse(absolute_url)
                if parsed.netloc == domain:
                    links.add(absolute_url)
            for link in links:
                if link not in visited:
                    queue.append((link, current_depth + 1))
        await asyncio.sleep(delay)
    return vulnerable, errors, pages_crawled

async def process_single_url(session, semaphore, url, payloads, output_file, delay, retries, depth, max_pages, verify_delay):
    try:
        vuln, err, pages = await crawl_website(
            session, semaphore, url, payloads,
            output_file, delay, retries, depth, max_pages, verify_delay
        )
        return {'vulnerable': vuln, 'errors': err, 'pages': pages}
    except Exception as e:
        log(f"Error processing {url}: {str(e)}", "w")
        return {'vulnerable': 0, 'errors': 1, 'pages': 0}

async def process_batch(session, semaphore, batch, payloads, output_file, delay, retries, depth, max_pages, verify_delay):
    tasks = []
    for url in batch:
        if not url.startswith(('http://', 'https://')):
            tasks.append(process_single_url(
                session, semaphore, f'http://{url}', payloads,
                output_file, delay, retries, depth, max_pages, verify_delay
            ))
            tasks.append(process_single_url(
                session, semaphore, f'https://{url}', payloads,
                output_file, delay, retries, depth, max_pages, verify_delay
            ))
        else:
            tasks.append(process_single_url(
                session, semaphore, url, payloads,
                output_file, delay, retries, depth, max_pages, verify_delay
            ))
    results = await asyncio.gather(*tasks)
    return {
        'vulnerable': sum(r['vulnerable'] for r in results),
        'errors': sum(r['errors'] for r in results),
        'pages': sum(r['pages'] for r in results)
    }

async def run_scanner(args):
    if not args.url and not args.list:
        log("Error: You must specify either -u for single URL or -l for URL list", "e")
        return

    def url_generator():
        if args.url:
            yield args.url
        if args.list:
            with open(args.list, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        yield url

    payloads = DEFAULT_PAYLOADS
    if args.payloads and os.path.exists(args.payloads):
        with open(args.payloads, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]

    if args.output:
        open(args.output, 'w').close()

    log(f"Starting Scan", "i")
    log(f"Using {len(payloads)} payloads", "i")
    if args.output:
        log(f"Saving results to {args.output}", "i")
    log("Configuration:")
    print(f" | Concurrency: {args.concurrency}")
    print(f" | Delay: {args.delay}s")
    print(f" | Retries: {args.retries}")
    print(f" | Depth: {args.depth}")
    print(f" | Max pages: {args.max_pages}")
    print(f" | Verification delay: {args.verify_delay}s\n")

    time.sleep(3)

    connector = aiohttp.TCPConnector(limit=args.concurrency, force_close=True)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    semaphore = asyncio.Semaphore(args.concurrency)

    total_vulnerable = 0
    total_errors = 0
    total_pages = 0
    start_time = time.time()

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers={'User-Agent': get_random_user_agent()}
    ) as session:
        batch_size = 100
        current_batch = []
        for url in url_generator():
            current_batch.append(url)
            if len(current_batch) >= batch_size:
                results = await process_batch(
                    session, semaphore, current_batch, payloads,
                    args.output, args.delay, args.retries,
                    args.depth, args.max_pages, args.verify_delay
                )
                total_vulnerable += results['vulnerable']
                total_errors += results['errors']
                total_pages += results['pages']
                current_batch = []
                log(f"Progress: {total_pages} pages processed, {total_vulnerable} confirmed vulnerabilities", "i")
        if current_batch:
            results = await process_batch(
                session, semaphore, current_batch, payloads,
                args.output, args.delay, args.retries,
                args.depth, args.max_pages, args.verify_delay
            )
            total_vulnerable += results['vulnerable']
            total_errors += results['errors']
            total_pages += results['pages']
    print()
    log("Scan completed", "s")
    print(f" | Pages crawled: {total_pages}")
    print(f" | Vulnerabilities: {total_vulnerable}")
    print(f" | Errors encountered: {total_errors}")
    print(f" | Time taken: {time.time() - start_time:.2f} seconds\n")