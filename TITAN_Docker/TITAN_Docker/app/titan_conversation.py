import requests
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import os

# List of excluded domains/URLs
excluded_domains = [
    "https://socprime.com/tag/ransomware/",  # Add any domains/URLs you want to skip here
    "https://example.com/",  # You can add more excluded domains or specific URLs here
]

# Extract and format all tables, removing hyperlinks, images, and SVG elements, and add the source URL under each table
def extract_tables_from_file(file_path, url):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            soup = BeautifulSoup(file, 'html.parser')

        tables_html = ""
        tables = soup.find_all("table")

        if not tables:  # If no tables are found, indicate this in the report
            return f"<p>No tables found on {url}</p>"

        for table in tables:
            # Remove hyperlinks, images, and svg tags
            for a_tag in table.find_all('a'):
                a_tag.unwrap()  # Remove <a> tag but keep the text

            for img_tag in table.find_all('img'):
                img_tag.decompose()  # Remove <img> tags entirely

            for svg_tag in table.find_all('svg'):
                svg_tag.decompose()  # Remove <svg> tags entirely

            # Extract the entire <table> including any nested elements like <thead>, <tbody>, <caption>
            table_caption = table.find('caption')  # Extract caption if available
            if table_caption:
                caption_html = f"<caption>{table_caption.get_text()}</caption>"
            else:
                caption_html = ""

            # Convert the table and caption to string including all nested content
            table_html = str(table)
            tables_html += caption_html + table_html + f"<br><br><p>Source: <a href='{url}'>{url}</a></p><br>"  # Add the source URL underneath each table
        return tables_html
    except Exception as e:
        print(f"Error extracting tables from {file_path}: {e}")
        return f"<p>Error extracting tables from {url}</p>"

# Check if a URL belongs to an excluded domain
def is_excluded(url):
    for excluded_domain in excluded_domains:
        if excluded_domain in url:
            return True
    return False

# Perform a search using Firefox and Selenium, handle pagination, and return file paths and URLs
def search_with_firefox_and_save(query):
    try:
        # Setup Firefox options for headless mode
        options = Options()
        options.headless = True
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        print(f"Running Firefox in headless mode for query: {query}")

        service = Service(executable_path="/usr/local/bin/geckodriver")
        valid_count = 0  # To keep track of valid scraped URLs
        file_paths = []
        urls = []

        # Start Firefox to perform the search
        driver = webdriver.Firefox(service=service, options=options)

        while valid_count < 20:
            try:
                # Perform a Google search for the query or move to the next page
                if valid_count == 0:
                    driver.get(f"https://www.google.com/search?q={query}")
                else:
                    try:
                        next_button = driver.find_element(By.ID, "pnnext")
                        next_button.click()
                    except Exception:
                        print("No more pages to search.")
                        break

                print(f"Performed search or moved to the next page for: {query}")

                # Wait for the results to load before extracting URLs
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, 'div.g a')))
                search_results = driver.find_elements(By.CSS_SELECTOR, 'div.g a')
                result_urls = [result.get_attribute('href') for result in search_results if result.get_attribute('href')]

                # Filter out any Google redirect URLs or invalid links
                result_urls = [url for url in result_urls if "google.com" not in url and url.startswith("http")]

                url_index = 0

                # Scrape valid URLs from the page
                while valid_count < 20 and url_index < len(result_urls):
                    url = result_urls[url_index]
                    url_index += 1

                    # Skip excluded domains
                    if is_excluded(url):
                        print(f"Skipping excluded URL: {url}")
                        continue

                    try:
                        print(f"Scraping URL: {url}")

                        # Navigate to the URL and save the source
                        driver.get(url)

                        # Wait for the page to load fully
                        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "html")))

                        # Save the source code to a file
                        file_path = f"website_source_{valid_count}.html"
                        page_source = driver.page_source
                        with open(file_path, 'w', encoding='utf-8') as file:
                            file.write(page_source)

                        file_paths.append(file_path)
                        urls.append(url)
                        valid_count += 1

                        print(f"Saved source code to {file_path}")
                    except Exception as e:
                        print(f"Error scraping URL {url}: {e}")

            except Exception as e:
                print(f"Error during search: {e}")
                break

        if valid_count < 20:
            print(f"Warning: Only {valid_count} valid URLs were processed.")

        driver.quit()
        return file_paths, urls
    except Exception as e:
        print(f"Error performing search with Firefox: {str(e)}")
        return [], []

# Generate a professional HTML report with enforced white background and black text
def generate_html_report(threat_name, tables):
    html_content = f"""
    <html>
        <head>
            <title>IOC Report - {threat_name.capitalize()} Ransomware</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    margin: 40px; 
                    background-color: white !important;  /* Ensure white background */
                    color: black !important;  /* Ensure text color is black */
                }}
                h1 {{ color: #2E86C1 !important; }}
                h2 {{ color: #21618C !important; margin-bottom: 5px !important; }}
                p {{ font-size: 14px !important; line-height: 1.6 !important; margin-bottom: 15px !important; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background-color: white !important; color: black !important; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2 !important; }}
                td {{ background-color: white !important; color: black !important; }}
                .content-section {{ margin-bottom: 20px; }}
                .footer {{ font-size: 12px; color: #5D6D7E; margin-top: 40px; text-align: center; }}
            </style>
        </head>
        <body>
            <h1>IOC Report: {threat_name.capitalize()} Ransomware</h1>

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

# Main process to search and generate a report
def generate_ioc_report(threat_name):
    print(f"Generating IOC report for {threat_name}...")

    # Search and download the IOCs content
    iocs_file_paths, urls = search_with_firefox_and_save(f"{threat_name} ransomware IOCs")

    tables = ""
    # Extract tables from downloaded files, append even if no tables are found
    for file_path, url in zip(iocs_file_paths, urls):
        extracted_tables = extract_tables_from_file(file_path, url)
        tables += extracted_tables  # Append whatever is found

    # Generate the final HTML report
    generate_html_report(threat_name, tables)

# Main loop to keep asking questions until 'exit' is typed
if __name__ == "__main__":
    while True:
        question = input("Type 'generate IOC report on [threat_name]' or 'exit' to quit: ").strip().lower()
        if question == "exit":
            print("Exiting the conversation. Goodbye!")
            break
        elif question.startswith("generate ioc report on"):
            threat_name = question.replace("generate ioc report on", "").strip()
            if threat_name:
                generate_ioc_report(threat_name)
            else:
                print("Please provide a valid threat name.")
        else:
            print("Invalid command. Try again.")

