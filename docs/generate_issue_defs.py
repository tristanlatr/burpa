import bs4
import requests
import json

# Generates a mapping from the BurpSuite issue ID to the CWE links.
if __name__ == "__main__":
    html = requests.get('https://portswigger.net/kb/issues').text
    soup = bs4.BeautifulSoup(html, features="lxml")

    issues = {}
    table = soup.select_one('#MainContent > table > tbody')
    
    for tr in table.children:
        if not isinstance(tr, bs4.Tag):
            continue

        row_items = list(tr.children)

        identifier = row_items[7].get_text().strip()
        classifications = ' '.join(str(i) for i in row_items[9].find_all('a'))

        issues[identifier] = classifications
    
    print(json.dumps(issues, indent=4))
