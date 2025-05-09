import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import time
import argparse
import logging
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

class WebsiteCrawler:
    def __init__(self, start_url, max_depth=3, max_workers=20, use_selenium=True, thread_count=None, 
                 security_scan=False, include_external_domains=False, scan_fragments=False):
        """
        Initialize the WebsiteCrawler.
        
        Args:
            start_url (str): The starting URL to crawl
            max_depth (int): Maximum depth to crawl
            max_workers (int): Maximum number of concurrent workers for URL processing
            use_selenium (bool): Whether to use Selenium for JavaScript-rendered content
            thread_count (int): Number of threads to use for the thread pool (None = auto)
            security_scan (bool): Enable security scanning features
            include_external_domains (bool): Allow crawling external domains
            scan_fragments (bool): Include URL fragments in scanning (for client-side vulns)
        """
        self.start_url = start_url
        self.max_depth = max_depth
        self.max_workers = max_workers
        self.use_selenium = use_selenium
        self.thread_count = thread_count
        self.security_scan = security_scan
        self.include_external_domains = include_external_domains
        self.scan_fragments = scan_fragments
        
        # Extract domain info
        parsed_url = urlparse(start_url)
        self.base_domain = parsed_url.netloc
        self.base_scheme = parsed_url.scheme
        
        # Data structures to store results
        self.visited_urls = set()
        self.nodes = set()  # All unique pages
        self.paths = set()  # All unique links
        
        # Security-related data structures
        self.potential_vulns = []  # Store potential vulnerabilities
        self.hidden_paths = []     # Store potentially hidden paths
        self.interesting_findings = []  # Store other interesting findings
        self.probed_paths = set()  # Track already probed paths
        
        # Get logger
        self.logger = logging.getLogger('WebsiteCrawler')
        
        # Initialize Selenium if needed
        if self.use_selenium:
            self._setup_selenium()
    
    def _setup_selenium(self):
        """Set up Selenium WebDriver with headless Chrome."""
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-infobars")
        chrome_options.add_argument("--disable-notifications")
        # Reduce memory usage
        chrome_options.add_argument("--js-flags=--max-old-space-size=512")
        # Increase performance
        chrome_options.add_argument("--blink-settings=imagesEnabled=false")
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(20)  # Reduced from 30 to 20 for faster processing
            self.logger.debug("Selenium WebDriver initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Selenium: {e}")
            self.use_selenium = False
            self.logger.warning("Falling back to requests-only mode")
    
    def _normalize_url(self, url, base_url):
        """Normalize a URL to absolute form and filter out unwanted types."""
        # Make the URL absolute
        full_url = urljoin(base_url, url)
        
        # Parse the URL
        parsed = urlparse(full_url)
        
        # Filter out unwanted URL types
        if parsed.scheme not in ('http', 'https'):
            return None
            
        # For security scanning, we can optionally include external domains
        # But by default we stay within the same domain
        if parsed.netloc != self.base_domain and not self.include_external_domains:
            return None
            
        # Remove fragments from URLs unless we're looking for client-side vulnerabilities
        if not self.scan_fragments:
            full_url = full_url.split('#')[0]
        
        # Check for common file extensions to exclude
        # In vulnerability scanning mode, we might want to include some of these
        if not self.security_scan:
            excluded_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js']
            if any(full_url.lower().endswith(ext) for ext in excluded_extensions):
                return None
            
        return full_url
    
    def _extract_links_from_html(self, html_content, base_url):
        """Extract links from HTML content."""
        links = set()
        self.logger.debug(f"Parsing HTML content from {base_url}")
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find all <a> tags
        anchor_count = 0
        valid_anchor_count = 0
        for anchor in soup.find_all('a', href=True):
            anchor_count += 1
            href = anchor['href']
            normalized_url = self._normalize_url(href, base_url)
            if normalized_url:
                valid_anchor_count += 1
                links.add(normalized_url)
        
        self.logger.debug(f"Found {anchor_count} anchor tags, {valid_anchor_count} valid")
        
        # Find URLs in source code using regex
        url_pattern = r'(?:href|src|url|action|data-url)=["\']([^"\']+)["\']'
        regex_count = 0
        valid_regex_count = 0
        for match in re.finditer(url_pattern, str(soup)):
            regex_count += 1
            potential_url = match.group(1)
            normalized_url = self._normalize_url(potential_url, base_url)
            if normalized_url:
                valid_regex_count += 1
                links.add(normalized_url)
        
        self.logger.debug(f"Found {regex_count} regex matches, {valid_regex_count} valid")
        
        # Look for other potential navigation elements
        nav_elements = soup.find_all(['nav', 'menu'])
        if nav_elements:
            self.logger.debug(f"Found {len(nav_elements)} navigation elements")
        
        # If security scanning is enabled, look for hidden paths
        if self.security_scan:
            potential_paths = self._find_hidden_paths(base_url, html_content)
            if potential_paths:
                links.update(potential_paths)
                self.logger.debug(f"Found {len(potential_paths)} potential hidden paths")
            
            # Scan for vulnerabilities
            try:
                self._scan_for_vulnerabilities(base_url, html_content)
            except Exception as e:
                self.logger.error(f"Error during vulnerability scanning: {str(e)}")
        
        self.logger.debug(f"Total unique links found: {len(links)}")
        return links
    
    def _extract_links_from_selenium(self, url):
        """Use Selenium to extract links from JavaScript-rendered content."""
        if not self.use_selenium:
            self.logger.debug("Selenium extraction skipped (disabled)")
            return set()
            
        links = set()
        try:
            self.logger.debug(f"Loading URL in Selenium: {url}")
            start_time = time.time()
            self.driver.get(url)
            
            try:
                self.logger.debug("Waiting for page body to load...")
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                load_time = time.time() - start_time
                self.logger.debug(f"Page loaded in {load_time:.2f}s")
                
                # Wait a bit more for any JavaScript to execute
                self.logger.debug("Waiting for JavaScript to execute...")
                time.sleep(2)
            except TimeoutException:
                self.logger.warning(f"Timeout waiting for body element at {url}")
                return set()
            
            # Get links from <a> tags
            self.logger.debug("Finding <a> tags...")
            a_tags = self.driver.find_elements(By.TAG_NAME, "a")
            self.logger.debug(f"Found {len(a_tags)} <a> tags")
            
            a_tag_count = 0
            valid_a_tag_count = 0
            for a_tag in a_tags:
                a_tag_count += 1
                try:
                    href = a_tag.get_attribute("href")
                    if href:
                        normalized_url = self._normalize_url(href, url)
                        if normalized_url:
                            valid_a_tag_count += 1
                            links.add(normalized_url)
                except Exception as e:
                    self.logger.debug(f"Error extracting href from <a> tag: {str(e)}")
                    continue
            
            self.logger.debug(f"Processed {a_tag_count} <a> tags, {valid_a_tag_count} valid links")
            
            # Find clickable elements like buttons
            self.logger.debug("Finding clickable elements...")
            try:
                clickable_elements = self.driver.find_elements(
                    By.XPATH, 
                    "//*[self::button or @role='button' or @type='button' or contains(@class, 'btn')]"
                )
                self.logger.debug(f"Found {len(clickable_elements)} clickable elements")
            except Exception as e:
                self.logger.debug(f"Error finding clickable elements: {str(e)}")
                clickable_elements = []
            
            button_count = 0
            valid_button_count = 0
            for element in clickable_elements:
                button_count += 1
                try:
                    # Extract href or onclick attributes
                    onclick = element.get_attribute("onclick")
                    if onclick and "location" in onclick:
                        self.logger.debug(f"Found onclick handler: {onclick}")
                        # Try to extract URL from onclick handler
                        match = re.search(r'[\'"](https?://[^\'"]+)[\'"]', onclick)
                        if match:
                            normalized_url = self._normalize_url(match.group(1), url)
                            if normalized_url:
                                valid_button_count += 1
                                links.add(normalized_url)
                                self.logger.debug(f"Extracted URL from onclick: {normalized_url}")
                except Exception as e:
                    self.logger.debug(f"Error processing clickable element: {str(e)}")
                    continue
            
            self.logger.debug(f"Processed {button_count} buttons, {valid_button_count} valid links")
            
            # Get page source after JavaScript execution
            self.logger.debug("Getting final page source after JavaScript execution")
            page_source = self.driver.page_source
            more_links = self._extract_links_from_html(page_source, url)
            
            pre_count = len(links)
            links.update(more_links)
            post_count = len(links)
            self.logger.debug(f"Added {post_count - pre_count} additional links from page source")
            
        except TimeoutException:
            self.logger.warning(f"Timeout loading {url} with Selenium")
        except Exception as e:
            self.logger.error(f"Error processing {url} with Selenium: {str(e)}")
            self.logger.debug(f"Exception details: {type(e).__name__}: {str(e)}")
            
        self.logger.debug(f"Selenium extraction complete: found {len(links)} total links")
        return links
    
    def _crawl_url(self, url, depth):
        """Crawl a single URL and return found links."""
        if depth > self.max_depth or url in self.visited_urls:
            self.logger.debug(f"Skipping {url}: {'max depth exceeded' if depth > self.max_depth else 'already visited'}")
            return set()
            
        self.visited_urls.add(url)
        self.nodes.add(url)
        self.logger.info(f"Crawling [{depth}/{self.max_depth}]: {url}")
        
        start_time = time.time()
        
        # First try with Selenium if enabled
        links = set()
        if self.use_selenium:
            self.logger.debug(f"Attempting to extract links using Selenium from: {url}")
            links = self._extract_links_from_selenium(url)
            self.logger.debug(f"Found {len(links)} links using Selenium")
        
        # Fall back to requests if Selenium failed or is disabled
        if not links and self.use_selenium:
            self.logger.info(f"Falling back to requests for {url}")
            
        if not self.use_selenium or not links:
            try:
                self.logger.debug(f"Sending HTTP request to: {url}")
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    self.logger.debug(f"HTTP request successful: {url} (status: {response.status_code})")
                    
                    # If security scanning enabled, check response headers
                    if self.security_scan:
                        try:
                            self._scan_for_vulnerabilities(url, response.text, response)
                        except Exception as e:
                            self.logger.error(f"Error during vulnerability scanning: {str(e)}")
                    
                    links.update(self._extract_links_from_html(response.text, url))
                    self.logger.debug(f"Found {len(links)} links using requests")
                else:
                    self.logger.warning(f"HTTP request failed: {url} (status: {response.status_code})")
                    
                    # For security scanning, non-200 responses might be interesting
                    if self.security_scan and response.status_code != 404:
                        self.interesting_findings.append({
                            'type': 'non_200_response',
                            'url': url,
                            'status_code': response.status_code,
                            'reason': response.reason
                        })
            except requests.RequestException as e:
                self.logger.error(f"Request error for {url}: {str(e)}")
        
        # Add paths (links) between nodes
        new_paths = 0
        for link in links:
            if link != url:  # Avoid self-loops
                if (url, link) not in self.paths:
                    self.paths.add((url, link))
                    new_paths += 1
        
        elapsed_time = time.time() - start_time
        self.logger.debug(f"Finished crawling {url} in {elapsed_time:.2f}s: found {len(links)} links, added {new_paths} new paths")
        
        # If we're in security scan mode, try some additional paths
        if self.security_scan:
            # We'll do this separately to avoid interfering with normal crawling
            self._probe_additional_paths(url)
        
        return links
    
    def crawl(self):
        """Start the crawling process from the initial URL."""
        self.logger.info(f"Starting crawl from {self.start_url}")
        self.logger.info(f"Configuration: max_depth={self.max_depth}, max_workers={self.max_workers}, use_selenium={self.use_selenium}")
        start_time = time.time()
        
        # Determine thread count for ThreadPoolExecutor
        if self.thread_count is None:
            import multiprocessing
            self.thread_count = max(4, multiprocessing.cpu_count() * 2)  # Use 2x CPU cores by default
        
        self.logger.info(f"Using {self.thread_count} threads for processing")
        
        # Queue of (url, depth) pairs to process
        queue = [(self.start_url, 0)]
        
        # Keep track of URLs that are queued but not yet visited
        # This prevents the same URL from being added to the queue multiple times
        queued_urls = {self.start_url}
        
        batch_count = 0
        total_urls_processed = 0
        
        self.logger.debug(f"Initial queue contains 1 URL: {self.start_url}")
        
        # Create a thread pool that will be reused
        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            while queue:
                batch_count += 1
                # Process up to max_workers URLs concurrently
                batch = queue[:self.max_workers]
                queue = queue[self.max_workers:]
                
                self.logger.debug(f"Processing batch #{batch_count} with {len(batch)} URLs")
                batch_start_time = time.time()
                
                # Process URLs in parallel using the thread pool
                futures = []
                for url, depth in batch:
                    # Remove from queued set when processing
                    queued_urls.discard(url)
                    futures.append(executor.submit(self._crawl_url, url, depth))
                
                # Collect results
                results = []
                for i, future in enumerate(futures):
                    try:
                        url = batch[i][0]
                        links = future.result()
                        results.append((url, links))
                    except Exception as e:
                        self.logger.error(f"Error processing URL {batch[i][0]}: {str(e)}")
                        results.append((batch[i][0], set()))
                
                batch_elapsed_time = time.time() - batch_start_time
                total_urls_processed += len(batch)
                
                # Add new URLs to the queue
                new_urls_added = 0
                for url, links in results:
                    current_depth = next(depth for u, depth in batch if u == url)
                    if current_depth < self.max_depth:
                        for link in links:
                            # Only add URLs that aren't already visited or queued
                            if link not in self.visited_urls and link not in queued_urls:
                                queue.append((link, current_depth + 1))
                                queued_urls.add(link)
                                new_urls_added += 1
                
                self.logger.debug(f"Batch #{batch_count} completed in {batch_elapsed_time:.2f}s: processed {len(batch)} URLs, added {new_urls_added} new URLs to queue")
                
                # Log progress every 5 batches or if queue is getting large
                if batch_count % 5 == 0 or len(queue) > 1000:
                    self.logger.info(f"Progress: {total_urls_processed} URLs processed, {len(self.nodes)} unique nodes found, {len(queue)} URLs in queue")
        
        elapsed_time = time.time() - start_time
        urls_per_second = total_urls_processed / elapsed_time if elapsed_time > 0 else 0
        
        self.logger.info(f"Crawl completed in {elapsed_time:.2f} seconds ({urls_per_second:.2f} URLs/second)")
        self.logger.info(f"Found {len(self.nodes)} nodes and {len(self.paths)} paths")
        self.logger.info(f"Total batches: {batch_count}, total URLs processed: {total_urls_processed}")
        
        # Clean up Selenium if used
        if self.use_selenium:
            try:
                self.logger.debug("Closing Selenium WebDriver")
                self.driver.quit()
                self.logger.debug("Selenium WebDriver closed successfully")
            except Exception as e:
                self.logger.debug(f"Error closing Selenium WebDriver: {str(e)}")
        
        return self.nodes, self.paths
    
    def _find_hidden_paths(self, url, html_content, page_source=None):
        """
        Look for potentially hidden paths, backup files, and misconfigured endpoints.
        
        Args:
            url (str): The URL being crawled
            html_content (str): The HTML content of the page
            page_source (str): Optional Selenium page source
        """
        if not self.security_scan:
            return set()
            
        base_url = url
        parsed_url = urlparse(url)
        base_path = parsed_url.path
        
        # Build a list of potential paths to check
        potential_paths = set()
        
        # Make sure we're only appending patterns to directories, not files
        # Check if the path looks like a file (has extension)
        path_parts = base_path.split('/')
        if path_parts and '.' in path_parts[-1]:
            # Last part is likely a file, use its directory
            dirname = '/'.join(path_parts[:-1])
            if not dirname:
                dirname = '/'
        else:
            # Path is likely a directory
            dirname = base_path
            
        # Common patterns for hidden files and directories
        patterns = [
            # Backup files
            ".bak", ".old", ".backup", "~", ".swp", ".tmp",
            # Config files
            ".env", ".config", "config.php", "settings.php", ".ini",
            # Version control
            ".git", ".svn", ".hg",
            # Debug/development endpoints
            "test.php", "dev.php", "staging.php", "debug.php", "phpinfo.php",
            # Admin interfaces
            "admin", "administrator", "wp-admin", "cpanel", "dashboard",
            # API endpoints
            "api", "v1", "v2", "graphql", "graphiql",
            # Log files
            ".log", "logs", "error_log",
            # Database files
            ".sql", ".db", ".sqlite",
            # Documentation
            "README", "CHANGELOG", "LICENSE",
            # Common vulnerable paths
            "upload.php", "file-upload", "import"
        ]
        
        # Normalize the base directory for appending paths
        base_dir = parsed_url.scheme + "://" + parsed_url.netloc + dirname
        if not base_dir.endswith('/'):
            base_dir += '/'
            
        # Create potential paths by joining properly
        for pattern in patterns:
            # Normalize the URL properly
            potential_path = urljoin(base_dir, pattern)
            potential_paths.add(potential_path)
        
        # Look for clues in HTML comments
        comment_pattern = r'<!--(.+?)-->'
        for match in re.finditer(comment_pattern, html_content):
            comment_text = match.group(1).strip()
            
            # Look for paths in comments
            path_pattern = r'(?:href|src|url|path|location|redirect)=[\"\']?([/\w\.-]+)[\"\']?'
            for path_match in re.finditer(path_pattern, comment_text):
                path = path_match.group(1)
                if path.startswith('/') or '.' in path:
                    normalized_url = self._normalize_url(path, base_url)
                    if normalized_url:
                        potential_paths.add(normalized_url)
                        # Record the finding
                        if not any(item.get('url') == normalized_url and item.get('source') == f"HTML comment in {url}" for item in self.hidden_paths):
                            self.hidden_paths.append({
                                'url': normalized_url,
                                'source': f"HTML comment in {url}",
                                'context': comment_text[:50] + '...' if len(comment_text) > 50 else comment_text
                            })
        
        # Look for JavaScript files with potential endpoints
        js_pattern = r'<script[^>]+src=[\"\']([^\"\']+\.js)[\"\']'
        for match in re.finditer(js_pattern, html_content):
            js_url = match.group(1)
            normalized_js_url = self._normalize_url(js_url, base_url)
            if normalized_js_url:
                potential_paths.add(normalized_js_url)
        
        # Look for disabled form elements and hidden inputs
        form_patterns = [
            r'<input[^>]+type=["\']hidden["\'][^>]+value=["\'](.*?)["\']',
            r'<form[^>]+action=["\'](.*?)["\']',
            r'<[^>]+disabled[^>]+>'
        ]
        
        for pattern in form_patterns:
            for match in re.finditer(pattern, html_content):
                if len(match.groups()) > 0:
                    value = match.group(1)
                    if value.startswith('/') or '.' in value:
                        normalized_url = self._normalize_url(value, base_url)
                        if normalized_url:
                            potential_paths.add(normalized_url)
                            # Record the finding
                            if not any(item.get('url') == normalized_url and item.get('source') == f"Form element in {url}" for item in self.hidden_paths):
                                self.hidden_paths.append({
                                    'url': normalized_url,
                                    'source': f"Form element in {url}",
                                    'context': match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0)
                                })
        
        # Look for robots.txt disallowed paths
        robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
        if robots_url not in self.probed_paths:
            self.probed_paths.add(robots_url)
            try:
                response = requests.get(robots_url, timeout=10)
                if response.status_code == 200:
                    for line in response.text.splitlines():
                        if line.lower().startswith('disallow:'):
                            disallowed_path = line.split(':', 1)[1].strip()
                            if disallowed_path:
                                normalized_url = self._normalize_url(disallowed_path, base_url)
                                if normalized_url:
                                    potential_paths.add(normalized_url)
                                    # Record the finding
                                    if not any(item.get('url') == normalized_url and item.get('source') == "robots.txt" for item in self.hidden_paths):
                                        self.hidden_paths.append({
                                            'url': normalized_url,
                                            'source': "robots.txt",
                                            'context': line
                                        })
            except Exception as e:
                self.logger.debug(f"Error checking robots.txt: {str(e)}")
            
        # Check for sitemap.xml
        sitemap_url = f"{parsed_url.scheme}://{parsed_url.netloc}/sitemap.xml"
        if sitemap_url not in self.probed_paths:
            self.probed_paths.add(sitemap_url)
            try:
                response = requests.get(sitemap_url, timeout=10)
                if response.status_code == 200:
                    # Extract URLs from sitemap
                    sitemap_urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                    for sitemap_url in sitemap_urls:
                        normalized_url = self._normalize_url(sitemap_url, base_url)
                        if normalized_url:
                            potential_paths.add(normalized_url)
            except Exception as e:
                self.logger.debug(f"Error checking sitemap.xml: {str(e)}")
        
        # Try common backup patterns for current page
        if path_parts and '.' in path_parts[-1]:
            basename = path_parts[-1]
            backup_patterns = [
                basename + ".bak", basename + ".old", basename + ".backup", 
                basename + "~", basename + ".swp", basename + ".tmp",
                basename + ".copy", basename + "_old", basename + "_bak"
            ]
            
            for pattern in backup_patterns:
                backup_url = urljoin(base_dir, pattern)
                potential_paths.add(backup_url)
        
        # Update the list of potential vulnerabilities
        for path in potential_paths:
            if not any(item.get('url') == path and item.get('type') == 'potential_hidden_path' for item in self.interesting_findings):
                self.interesting_findings.append({
                    'type': 'potential_hidden_path',
                    'url': path,
                    'source_url': url
                })
        
        return potential_paths
    
    def _probe_additional_paths(self, base_url):
        """
        Probe for additional paths that might be hidden or vulnerable.
        
        Args:
            base_url (str): The base URL to use for building path combinations
        """
        if not self.security_scan:
            return
            
        parsed_url = urlparse(base_url)
        base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Common sensitive directories and files to check
        sensitive_paths = [
            # Common sensitive directories
            "/.git/", "/.svn/", "/.env", "/.well-known/",
            "/backup/", "/bak/", "/old/", "/temp/", "/tmp/",
            "/admin/", "/administrator/", "/wp-admin/", "/phpmyadmin/",
            "/config/", "/conf/", "/configuration/", "/settings/",
            "/dev/", "/development/", "/test/", "/testing/", "/staging/",
            
            # Common sensitive files
            "/robots.txt", "/sitemap.xml", "/error_log", "/debug.log", 
            "/server-status", "/server-info", "/phpinfo.php", "/info.php",
            "/.DS_Store", "/crossdomain.xml", "/web.config", "/.htaccess",
            "/readme.md", "/README.md", "/readme.txt", "/CHANGELOG.md",
            "/config.php", "/config.ini", "/config.json", "/settings.json",
            
            # API endpoints
            "/api/", "/v1/", "/v2/", "/graphql", "/swagger", "/docs", 
            "/swagger-ui.html", "/api-docs", "/api/health", "/status",
            
            # Upload endpoints (often vulnerable)
            "/upload.php", "/uploads/", "/file-upload/", "/import/", "/export/"
        ]
        
        # Check each sensitive path
        for path in sensitive_paths:
            # Use proper URL joining to avoid malformed URLs
            test_url = urljoin(base_domain, path)
            
            # Skip if already visited or probed
            if test_url in self.visited_urls or test_url in self.probed_paths:
                continue
                
            # Mark as probed to avoid duplicate work
            self.probed_paths.add(test_url)
            
            try:
                self.logger.debug(f"Probing hidden path: {test_url}")
                response = requests.head(test_url, timeout=10)
                
                # If we get a reasonable response (not 404), this might be interesting
                if response.status_code != 404:
                    self.logger.info(f"Found potential hidden path: {test_url} (Status: {response.status_code})")
                    
                    # Check if this finding is already recorded
                    if not any(item.get('url') == test_url for item in self.hidden_paths):
                        self.hidden_paths.append({
                            'url': test_url,
                            'status': response.status_code,
                            'source': 'Common path probe',
                            'context': f"Status code: {response.status_code}"
                        })
                    
                    # Add to nodes and paths if not already there
                    self.nodes.add(test_url)
                    if (base_url, test_url) not in self.paths:
                        self.paths.add((base_url, test_url))
                    
            except Exception as e:
                self.logger.debug(f"Error probing {test_url}: {str(e)}")
                
        # Try common backup files for specific pages
        path_parts = parsed_url.path.split('/')
        if path_parts and '.' in path_parts[-1]:
            filename = path_parts[-1]
            dirname = '/'.join(path_parts[:-1])
            if not dirname:
                dirname = '/'
                
            backup_extensions = [".bak", ".old", ".backup", "~", ".swp", ".tmp", ".copy"]
            
            for ext in backup_extensions:
                # Properly join URL using urljoin
                backup_url = urljoin(base_domain + dirname + '/', filename + ext)
                
                # Skip if already visited or probed
                if backup_url in self.visited_urls or backup_url in self.probed_paths:
                    continue
                    
                # Mark as probed to avoid duplicate work
                self.probed_paths.add(backup_url)
                
                try:
                    self.logger.debug(f"Checking backup file: {backup_url}")
                    response = requests.head(backup_url, timeout=10)
                    
                    if response.status_code != 404:
                        self.logger.info(f"Potential backup file found: {backup_url} (Status: {response.status_code})")
                        
                        # Check if this finding is already recorded
                        if not any(item.get('url') == backup_url for item in self.hidden_paths):
                            self.hidden_paths.append({
                                'url': backup_url,
                                'status': response.status_code,
                                'source': 'Backup file check',
                                'context': f"Backup of {filename}"
                            })
                        
                        # Add to nodes and paths if not already there
                        self.nodes.add(backup_url)
                        if (base_url, backup_url) not in self.paths:
                            self.paths.add((base_url, backup_url))
                
                except Exception as e:
                    self.logger.debug(f"Error checking backup file {backup_url}: {str(e)}")
    
    def _scan_for_vulnerabilities(self, url, html_content, response=None):
        """
        Scan for potential security issues in the page.
        
        Args:
            url (str): The URL being crawled
            html_content (str): The HTML content of the page
            response (Response): Optional requests response object for checking headers
        """
        if not self.security_scan:
            return
            
        self.logger.debug(f"Scanning for vulnerabilities in {url}")
            
        # Check for sensitive information exposure
        sensitive_patterns = [
            # API keys and tokens
            r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\'"]',
            r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\'"]',
            r'secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\'"]',
            # AWS specific
            r'AKIA[0-9A-Z]{16}',
            # Database connection strings
            r'(?:mysql|postgresql|mongodb|oracle)://\w+:\w+@',
            # Email addresses in non-visible elements
            r'<(?:input|meta)[^>]+value=["\']([\w.-]+@[\w.-]+\.\w+)["\']',
            # Passwords
            r'password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
            # IP addresses
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            # Social security numbers (US)
            r'\b\d{3}-\d{2}-\d{4}\b',
            # Credit card numbers
            r'\b(?:\d{4}[- ]?){3}\d{4}\b'
        ]
        
        for pattern in sensitive_patterns:
            for match in re.finditer(pattern, html_content):
                sensitive_data = match.group(0)
                context = html_content[max(0, match.start() - 20):min(len(html_content), match.end() + 20)]
                
                # Check if this finding is already recorded
                if not any(item.get('finding') == sensitive_data and item.get('url') == url for item in self.potential_vulns):
                    self.potential_vulns.append({
                        'type': 'sensitive_information_exposure',
                        'url': url,
                        'pattern': pattern,
                        'finding': sensitive_data,
                        'context': context.strip()
                    })
                
        # Check for insecure configurations
        if response:
            # Check security headers
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Referrer-Policy'
            ]
            
            missing_headers = []
            for header in security_headers:
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                # Check if this finding is already recorded for this URL
                if not any(item.get('type') == 'missing_security_headers' and item.get('url') == url for item in self.potential_vulns):
                    self.potential_vulns.append({
                        'type': 'missing_security_headers',
                        'url': url,
                        'missing_headers': missing_headers
                    })
            
            # Check for cookies without secure flags
            if 'Set-Cookie' in response.headers:
                cookies = response.headers.get('Set-Cookie')
                if 'secure' not in cookies.lower() or 'httponly' not in cookies.lower():
                    # Check if this finding is already recorded for this URL
                    if not any(item.get('type') == 'insecure_cookies' and item.get('url') == url for item in self.potential_vulns):
                        self.potential_vulns.append({
                            'type': 'insecure_cookies',
                            'url': url,
                            'cookies': cookies
                        })
        
        # Check for client-side vulnerabilities
        # XSS vectors
        xss_patterns = [
            r'<input[^>]+value=["\'](.*?)["\'][^>]*>',
            r'<textarea[^>]*>(.*?)</textarea>',
            r'document\.write\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*='
        ]
        
        for pattern in xss_patterns:
            for match in re.finditer(pattern, html_content):
                context = html_content[max(0, match.start() - 20):min(len(html_content), match.end() + 20)]
                
                # Check if this finding is already recorded for this URL
                if not any(item.get('pattern') == pattern and item.get('url') == url and item.get('context') == context.strip() for item in self.potential_vulns):
                    self.potential_vulns.append({
                        'type': 'potential_xss_vector',
                        'url': url,
                        'pattern': pattern,
                        'context': context.strip()
                    })
        
        # Look for CSRF vulnerabilities
        if '<form' in html_content and 'csrf' not in html_content.lower() and 'token' not in html_content.lower():
            # Check if this finding is already recorded for this URL
            if not any(item.get('type') == 'potential_csrf' and item.get('url') == url for item in self.potential_vulns):
                self.potential_vulns.append({
                    'type': 'potential_csrf',
                    'url': url,
                    'finding': 'Form without CSRF protection'
                })
            
        # Check for potentially vulnerable JavaScript libraries
        js_patterns = [
            r'jquery-(\d+\.\d+\.\d+)\.min\.js',
            r'bootstrap-(\d+\.\d+\.\d+)\.min\.js',
            r'angular(?:js)?-(\d+\.\d+\.\d+)\.min\.js',
            r'react-(\d+\.\d+\.\d+)\.min\.js',
            r'vue-(\d+\.\d+\.\d+)\.min\.js'
        ]
        
        for pattern in js_patterns:
            for match in re.finditer(pattern, html_content):
                library = match.group(0)
                version = match.group(1)
                
                # Check if this finding is already recorded for this URL
                if not any(item.get('library') == library and item.get('url') == url for item in self.interesting_findings):
                    self.interesting_findings.append({
                        'type': 'js_library',
                        'url': url,
                        'library': library,
                        'version': version
                    })
    
    def export_to_excel(self, output_file="website_structure.xlsx"):
        """Export the crawl results to an Excel file in a readable, organized format."""
        try:
            # Process nodes with additional information
            node_list = list(self.nodes)
            
            # Create a simplified path representation for each node
            node_paths = {}
            for source, target in self.paths:
                if source not in node_paths:
                    node_paths[source] = []
                node_paths[source].append(target)
            
            # Create categories of pages based on URL patterns
            def categorize_url(url):
                path = urlparse(url).path.lower()
                if path == '' or path == '/':
                    return 'Homepage'
                elif '/blog/' in path or '/news/' in path:
                    return 'Blog/News'
                elif '/product/' in path or '/shop/' in path or '/store/' in path:
                    return 'Products'
                elif '/about/' in path or '/about-us/' in path:
                    return 'About'
                elif '/contact/' in path:
                    return 'Contact'
                elif path.endswith(('.php', '.asp', '.aspx', '.jsp')):
                    return 'Dynamic Pages'
                else:
                    return 'Other'
            
            # Create structured node data
            nodes_data = []
            for i, url in enumerate(node_list, 1):
                parsed = urlparse(url)
                path = parsed.path if parsed.path else '/'
                outgoing_links = len(node_paths.get(url, []))
                incoming_links = sum(1 for source, target in self.paths if target == url)
                
                nodes_data.append({
                    'ID': i,
                    'URL': url,
                    'Path': path,
                    'Category': categorize_url(url),
                    'Outgoing Links': outgoing_links,
                    'Incoming Links': incoming_links
                })
            
            # Create nodes DataFrame with better organization
            nodes_df = pd.DataFrame(nodes_data)
            
            # Create a cleaner paths DataFrame
            paths_data = []
            for source, target in self.paths:
                # Make sure both source and target are in the node list
                if source in node_list and target in node_list:
                    source_id = node_list.index(source) + 1
                    target_id = node_list.index(target) + 1
                    
                    # Get simplified paths for readability
                    source_path = urlparse(source).path if urlparse(source).path else '/'
                    target_path = urlparse(target).path if urlparse(target).path else '/'
                    
                    paths_data.append({
                        'Source ID': source_id,
                        'Source URL': source,
                        'Source Path': source_path,
                        'Target ID': target_id,
                        'Target URL': target,
                        'Target Path': target_path
                    })
                else:
                    # Log that we're skipping this path due to missing nodes
                    self.logger.warning(f"Skipping path ({source} -> {target}) because one of the nodes is not in the node list")
            
            paths_df = pd.DataFrame(paths_data)
            
            # Create summary data
            categories = pd.DataFrame(nodes_df['Category'].value_counts()).reset_index()
            categories.columns = ['Category', 'Count']
            
            # Create a summary sheet data
            summary_data = {
                'Metric': [
                    'Total Pages (Nodes)',
                    'Total Links (Paths)',
                    'Average Links per Page',
                    'Max Outgoing Links',
                    'Page with Most Outgoing Links',
                    'Max Incoming Links',
                    'Page with Most Incoming Links',
                    'Crawl Depth Used',
                    'Base Domain'
                ],
                'Value': []
            }
            
            # Fill in the values, handling edge cases
            summary_values = []
            # Total Pages
            summary_values.append(len(self.nodes))
            # Total Links
            summary_values.append(len(self.paths))
            # Average Links per Page
            summary_values.append(round(len(self.paths) / len(self.nodes), 2) if self.nodes else 0)
            
            # Max Outgoing Links
            if not nodes_df.empty and 'Outgoing Links' in nodes_df.columns and len(nodes_df['Outgoing Links']) > 0:
                summary_values.append(max(nodes_df['Outgoing Links']))
                # Page with Most Outgoing Links
                max_outgoing_idx = nodes_df['Outgoing Links'].idxmax()
                if max_outgoing_idx is not None:
                    summary_values.append(nodes_df.loc[max_outgoing_idx, 'URL'])
                else:
                    summary_values.append('N/A')
            else:
                summary_values.append(0)
                summary_values.append('N/A')
            
            # Max Incoming Links
            if not nodes_df.empty and 'Incoming Links' in nodes_df.columns and len(nodes_df['Incoming Links']) > 0:
                summary_values.append(max(nodes_df['Incoming Links']))
                # Page with Most Incoming Links
                max_incoming_idx = nodes_df['Incoming Links'].idxmax()
                if max_incoming_idx is not None:
                    summary_values.append(nodes_df.loc[max_incoming_idx, 'URL'])
                else:
                    summary_values.append('N/A')
            else:
                summary_values.append(0)
                summary_values.append('N/A')
            
            # Remaining items
            summary_values.append(self.max_depth)
            summary_values.append(self.base_domain)
            
            summary_data['Value'] = summary_values
            summary_df = pd.DataFrame(summary_data)
            
            # Create security findings data if in security scan mode
            security_sheets = {}
            if self.security_scan:
                # Hidden paths
                if self.hidden_paths:
                    hidden_paths_df = pd.DataFrame(self.hidden_paths)
                    security_sheets['Hidden_Paths'] = hidden_paths_df
                
                # Potential vulnerabilities
                if self.potential_vulns:
                    vulns_df = pd.DataFrame(self.potential_vulns)
                    security_sheets['Vulnerabilities'] = vulns_df
                
                # Interesting findings
                if self.interesting_findings:
                    findings_df = pd.DataFrame(self.interesting_findings)
                    security_sheets['Interesting_Findings'] = findings_df
            
            # Write to Excel with proper formatting
            with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                # Summary sheet
                summary_df.to_excel(writer, sheet_name="Summary", index=False)
                categories.to_excel(writer, sheet_name="Summary", startrow=len(summary_data['Metric'])+2, index=False)
                
                # Set column widths for Summary
                worksheet = writer.sheets["Summary"]
                worksheet.column_dimensions['A'].width = 30
                worksheet.column_dimensions['B'].width = 50
                
                # Add header for categories
                worksheet.cell(row=len(summary_data['Metric'])+2, column=1).value = "Page Categories"
                
                # Nodes sheet with nice formatting
                nodes_df.to_excel(writer, sheet_name="Nodes", index=False)
                worksheet = writer.sheets["Nodes"]
                worksheet.column_dimensions['A'].width = 5
                worksheet.column_dimensions['B'].width = 60
                worksheet.column_dimensions['C'].width = 30
                worksheet.column_dimensions['D'].width = 15
                worksheet.column_dimensions['E'].width = 15
                worksheet.column_dimensions['F'].width = 15
                
                # Paths sheet
                paths_df.to_excel(writer, sheet_name="Paths", index=False)
                worksheet = writer.sheets["Paths"]
                worksheet.column_dimensions['A'].width = 10
                worksheet.column_dimensions['B'].width = 60
                worksheet.column_dimensions['C'].width = 30
                worksheet.column_dimensions['D'].width = 10
                worksheet.column_dimensions['E'].width = 60
                worksheet.column_dimensions['F'].width = 30
                
                # Security-related sheets if in security scan mode
                if self.security_scan:
                    for sheet_name, df in security_sheets.items():
                        df.to_excel(writer, sheet_name=sheet_name, index=False)
                        worksheet = writer.sheets[sheet_name]
                        # Set column widths
                        for i, col in enumerate(df.columns):
                            worksheet.column_dimensions[chr(65 + i)].width = 30
                
            self.logger.info(f"Results exported to {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error exporting to Excel: {str(e)}")
            return False


def main():
    """Main function to run the crawler from command line."""
    parser = argparse.ArgumentParser(description="Website Crawler and Path Finder")
    parser.add_argument("url", help="Starting URL to crawl")
    parser.add_argument("--output", "-o", default="website_structure.xlsx",
                        help="Output Excel file (default: website_structure.xlsx)")
    parser.add_argument("--depth", "-d", type=int, default=3,
                        help="Maximum crawl depth (default: 3)")
    parser.add_argument("--workers", "-w", type=int, default=20,
                        help="Maximum number of concurrent workers (default: 20)")
    parser.add_argument("--no-selenium", action="store_true",
                        help="Disable Selenium for JavaScript rendering")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging output")
    parser.add_argument("--threads", "-t", type=int, default=None,
                        help="Number of threads to use (default: auto, based on CPU count)")
    parser.add_argument("--security-scan", "-s", action="store_true",
                        help="Enable security scanning mode to find hidden and vulnerable paths")
    parser.add_argument("--include-external", "-e", action="store_true",
                        help="Include external domains in crawl (only with --security-scan)")
    parser.add_argument("--scan-fragments", "-f", action="store_true",
                        help="Include URL fragments in scan (for client-side vulnerabilities)")
    
    args = parser.parse_args()
    
    # Configure logging based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger('WebsiteCrawler')
    
    # Determine the number of threads to use
    if args.threads:
        # Use the user-specified thread count
        num_threads = args.threads
    else:
        # Automatically set threads based on CPU count with a minimum of 4
        import multiprocessing
        cpu_count = multiprocessing.cpu_count()
        num_threads = max(4, cpu_count * 2)  # Use 2x CPU cores as a default
    
    if args.verbose:
        logger.info("Verbose logging enabled")
        logger.debug(f"Arguments: {args}")
        logger.info(f"Using {num_threads} threads for crawling")
    
    # Security scan mode warning
    if args.security_scan:
        logger.warning("Security scanning mode enabled - use responsibly and only on authorized targets")
        if args.include_external:
            logger.warning("External domain scanning enabled - this may significantly increase scan time")
    
    # Initialize and run the crawler
    crawler = WebsiteCrawler(
        args.url,
        max_depth=args.depth,
        max_workers=args.workers,
        use_selenium=not args.no_selenium,
        thread_count=num_threads,
        security_scan=args.security_scan,
        include_external_domains=args.include_external and args.security_scan,
        scan_fragments=args.scan_fragments
    )
    
    crawler.crawl()
    crawler.export_to_excel(args.output)
    
    # Print summary of security findings if in security scan mode
    if args.security_scan:
        print("\n===== Security Scan Summary =====")
        print(f"Hidden Paths Found: {len(crawler.hidden_paths)}")
        print(f"Potential Vulnerabilities: {len(crawler.potential_vulns)}")
        print(f"Interesting Findings: {len(crawler.interesting_findings)}")
        print(f"Results exported to: {args.output}")
        print("=================================")


if __name__ == "__main__":
    main()