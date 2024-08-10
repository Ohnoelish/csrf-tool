import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import random
import time
import logging
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Banner
def print_banner():
    banner = """
    ******************************************
    *          C S R F   D E T E C T O R    *
    ******************************************
    """
    print(Fore.CYAN + banner + Style.RESET_ALL)

class CSRFScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.visited_urls = set()

    def fetch_page(self, url):
        try:
            response = requests.get(url, headers=self.random_headers(), timeout=10)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            logging.error(f"Error fetching page {url}: {e}")
            return None

    def random_headers(self):
        return {
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }

    def find_forms(self, page_content, base_url):
        soup = BeautifulSoup(page_content, 'html.parser')
        forms = soup.find_all('form')
        form_details = []
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'GET').upper()
            action_url = urljoin(base_url, action or '')
            inputs = [(input.get('name'), input.get('type')) for input in form.find_all('input')]
            form_details.append({
                'action_url': action_url,
                'method': method,
                'inputs': inputs
            })
        return form_details

    def check_csrf_token(self, inputs):
        return any(name == 'csrfToken' for name, _ in inputs)

    def check_cookie_attributes(self, cookies):
        return all('SameSite' in cookie for cookie in cookies)

    def check_headers(self, request, allowed_domains):
        referer = request.headers.get('Referer')
        origin = request.headers.get('Origin')
        return (referer and any(domain in referer for domain in allowed_domains)) or \
               (origin and any(domain in origin for domain in allowed_domains))

    def scan_url(self, url):
        logging.info(f"Scanning URL: {url}")
        response = self.fetch_page(url)
        if response:
            vulnerabilities = []
            forms = self.find_forms(response.text, url)
            for form in forms:
                if not self.check_csrf_token(form['inputs']):
                    vulnerabilities.append({
                        'type': 'CSRF vulnerability',
                        'details': f"Form action URL: {form['action_url']}\nMethod: {form['method']}\nInputs: {form['inputs']}"
                    })

            cookies = response.cookies.get_dict()
            if not self.check_cookie_attributes(cookies):
                vulnerabilities.append({
                    'type': 'Cookie SameSite Attribute Missing',
                    'details': 'Cookies do not have proper SameSite attributes.'
                })

            allowed_domains = [urlparse(url).netloc]
            if not self.check_headers(response.request, allowed_domains):
                vulnerabilities.append({
                    'type': 'Missing or Invalid Referer/Origin Headers',
                    'details': 'Missing or invalid Referer/Origin headers.'
                })

            return vulnerabilities
        else:
            return [{'type': 'Error', 'details': 'Unable to fetch page'}]

    def generate_report(self, vulnerabilities):
        if vulnerabilities:
            print(Fore.GREEN + "\nVulnerabilities Found:\n" + Style.RESET_ALL)
            for vuln in vulnerabilities:
                print(Fore.GREEN + f"Type: {vuln['type']}" + Style.RESET_ALL)
                print(Fore.GREEN + f"Details:\n{vuln['details']}" + Style.RESET_ALL)
                if vuln['type'] == 'CSRF vulnerability':
                    self.generate_poc(vuln['details'])
        else:
            print(Fore.RED + "\nNo vulnerabilities found." + Style.RESET_ALL)

    def generate_poc(self, details):
        form_details = details.split('\n')
        action_url = form_details[0].replace('Form action URL: ', '')
        method = form_details[1].replace('Method: ', '')
        inputs = form_details[2].replace('Inputs: ', '')

        poc_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CSRF PoC</title>
        </head>
        <body>
            <h1>CSRF Proof of Concept</h1>
            <form action="{action_url}" method="{method}">
                {inputs}
                <input type="submit" value="Submit"/>
            </form>
        </body>
        </html>
        """
        with open('poc.html', 'w') as file:
            file.write(poc_html)
        print(Fore.YELLOW + "\nProof of Concept HTML form generated: poc.html" + Style.RESET_ALL)

def main():
    print_banner()
    target_url = input("Enter the target URL: ").strip()
    scanner = CSRFScanner(target_url)
    vulnerabilities = scanner.scan_url(target_url)
    scanner.generate_report(vulnerabilities)
    logging.info("Scanning completed.")

if __name__ == '__main__':
    main()
