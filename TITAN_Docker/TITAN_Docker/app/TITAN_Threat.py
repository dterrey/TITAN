import requests
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import os

# Set the Firefox Profile Path
FIREFOX_PROFILE_PATH = "/home/titan/snap/firefox/common/.mozilla/firefox/mg6gr9r2.serenium"

# List of excluded domains/URLs
excluded_domains = [
    "https://socprime.com/tag/ransomware/",  
    "https://example.com/",  
]

# Function to extract tables from saved HTML files
def extract_tables_from_file(file_path, url):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            soup = BeautifulSoup(file, 'html.parser')

        tables_html = ""
        tables = soup.find_all("table")

        if not tables:  
            return f"<p>No tables found on {url}</p>"

        for table in tables:
            # Remove unnecessary elements
            for a_tag in table.find_all('a'):
                a_tag.unwrap()  

            for img_tag in table.find_all('img'):
                img_tag.decompose()  

            for svg_tag in table.find_all('svg'):
                svg_tag.decompose()  

            table_caption = table.find('caption')
            caption_html = f"<caption>{table_caption.get_text()}</caption>" if table_caption else ""

            table_html = str(table)
            tables_html += caption_html + table_html + f"<br><br><p>Source: <a href='{url}'>{url}</a></p><br>"

        return tables_html
    except Exception as e:
        print(f"Error extracting tables from {file_path}: {e}")
        return f"<p>Error extracting tables from {url}</p>"

# Function to check if a URL belongs to an excluded domain
def is_excluded(url):
    return any(excluded_domain in url for excluded_domain in excluded_domains)

# Perform a search using Firefox and Selenium
def search_with_firefox_and_save(query, max_results=10):
    try:
        options = Options()
        options.headless = False  # TEMPORARILY DISABLE HEADLESS MODE FOR DEBUGGING
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument("-profile")
        options.add_argument(FIREFOX_PROFILE_PATH)

        print(f"Using Firefox Profile: {FIREFOX_PROFILE_PATH}")

        service = Service(executable_path="/usr/local/bin/geckodriver")
        driver = webdriver.Firefox(service=service, options=options)

        # Perform Google Search
        driver.get(f"https://www.google.com/search?q={query}")

        # Wait until search results are present
        WebDriverWait(driver, 15).until(
            EC.presence_of_all_elements_located((By.CSS_SELECTOR, 'a'))
        )

        # Extract search result URLs
        search_results = driver.find_elements(By.CSS_SELECTOR, 'a')
        urls = [
            result.get_attribute('href') for result in search_results
            if result.get_attribute('href') and "google.com" not in result.get_attribute('href')
        ]

        print(f"Found {len(urls)} URLs.")

        # Initialize lists to store downloaded file paths and URLs
        file_paths = []

        # Visit each URL, download the content, and save it to a file
        valid_count = 0
        for url in urls[:max_results]:
            if is_excluded(url):
                print(f"Skipping excluded URL: {url}")
                continue

            try:
                print(f"Scraping URL: {url}")
                driver.get(url)

                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "html"))
                )

                # Save the source code to a file
                file_path = f"website_source_{valid_count}.html"
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(driver.page_source)

                file_paths.append(file_path)
                valid_count += 1

                print(f"Saved source code to {file_path}")

            except Exception as e:
                print(f"Error scraping URL {url}: {e}")

        driver.quit()
        return file_paths, urls[:valid_count]  # Return both lists

    except Exception as e:
        print(f"Error performing search with Firefox: {str(e)}")
        return [], []  # Return empty lists if an error occurs

# Function to generate an HTML report
def generate_html_report(threat_name, tables):
    html_content = f"""
    <html>
        <head>
            <title>IOC Report - {threat_name.capitalize()} Malware</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background-color: white; color: black; }}
                h1 {{ color: #2E86C1; }}
                h2 {{ color: #21618C; margin-bottom: 5px; }}
                p {{ font-size: 14px; line-height: 1.6; margin-bottom: 15px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background-color: white; color: black; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .content-section {{ margin-bottom: 20px; }}
                .footer {{ font-size: 12px; color: #5D6D7E; margin-top: 40px; text-align: center; }}
            </style>
        </head>
        <body>
            <h1>IOC Report: {threat_name.capitalize()} Malware</h1>

            <div class="content-section">
                <h2>Extracted Tables</h2>
                {tables}
            </div>

            <div class="footer">
                <p>Generated by TITAN-X. For further details, refer to external resources.</p>
            </div>
        </body>
    </html>
    """
    filename = f"{threat_name}_ioc_report.html"
    with open(filename, "w", encoding="utf-8") as file:
        file.write(html_content)

    print(f"HTML report generated: {filename}")

# Function to perform search and generate a report
def generate_ioc_report(threat_name):
    print(f"Generating IOC report for {threat_name}...")

    iocs_file_paths, urls = search_with_firefox_and_save(f"{threat_name} ransomware IOCs")

    tables = ""
    for file_path, url in zip(iocs_file_paths, urls):
        extracted_tables = extract_tables_from_file(file_path, url)
        tables += extracted_tables  

    generate_html_report(threat_name, tables)

# Main loop
if __name__ == "__main__":
    while True:
        question = input("Type 'generate IOC report on [threat_name]' or 'exit' to quit: ").strip().lower()
        if question == "exit":
            print("Exiting. Goodbye!")
            break
        elif question.startswith("generate ioc report on"):
            threat_name = question.replace("generate ioc report on", "").strip()
            if threat_name:
                generate_ioc_report(threat_name)
            else:
                print("Please provide a valid threat name.")
        else:
            print("Invalid command. Try again.")

