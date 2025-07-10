from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import re
import tldextract
import socket

def extract_features(url):
    try:
        # 🚀 Set up headless Chrome
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")

        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        page_source = driver.page_source
        soup = BeautifulSoup(page_source, "html.parser")

        # 🌐 Feature 1: IP Address in URL
        ip_flag = 1 if re.match(r"(http|https)://\d{1,3}\.", url) else 0

        # 🔗 Feature 2: Long URL
        long_url_flag = 1 if len(url) >= 54 else 0

        # 🔎 Feature 3: Short URL
        short_url_flag = 1 if len(url) <= 20 else 0

        # 📧 Feature 4: "@" Symbol in URL
        symbol_flag = 1 if "@" in url else 0

        # ➡️ Feature 5: Redirecting "//"
        redirect_flag = 1 if "//" in url[7:] else 0

        # 🚫 Feature 6: Prefix/Suffix "-"
        prefix_flag = 1 if "-" in tldextract.extract(url).domain else 0

        # 🧩 Feature 7: Subdomains
        ext = tldextract.extract(url)
        subdomain_count = ext.subdomain.count('.') + 1 if ext.subdomain else 0

        # 🔒 Feature 8: HTTPS
        https_flag = 1 if url.startswith("https://") else 0

        # 📅 Feature 9: Domain Registration Length (stubbed as 0 - phishing)
        domain_age_flag = 0  # This would require WHOIS check (left as 0 for demo)

        # 🌟 Feature 10: Favicon
        favicon_flag = 1 if soup.find("link", rel=lambda x: x and "icon" in x.lower()) else 0

        # 📶 Feature 11: Non-Standard Port
        port_flag = 1 if ":" in url.split("//")[-1] else 0

        # 🔐 Feature 12: HTTPS token in domain
        https_domain_flag = 1 if "https" in ext.domain else 0

        # 📥 Feature 13: RequestURL
        imgs = soup.find_all('img', src=True)
        total_imgs = len(imgs)
        external_imgs = sum(1 for img in imgs if url not in img['src'])
        request_url_flag = 1 if total_imgs > 0 and external_imgs / total_imgs > 0.5 else 0

        # 🔗 Feature 14: Anchor Tags
        anchors = soup.find_all('a', href=True)
        total_anchors = len(anchors)
        external_anchors = sum(1 for a in anchors if url not in a['href'])
        anchor_url_flag = 1 if total_anchors > 0 and external_anchors / total_anchors > 0.5 else 0

        # 📜 Feature 15: Scripts linking to other domains
        scripts = soup.find_all('script', src=True)
        total_scripts = len(scripts)
        external_scripts = sum(1 for s in scripts if url not in s['src'])
        script_links_flag = 1 if total_scripts > 0 and external_scripts / total_scripts > 0.5 else 0

        # 📄 Feature 16: SFH (server form handler)
        forms = soup.find_all('form', action=True)
        sfh_flag = 0
        for form in forms:
            action = form['action']
            if action == "" or action.startswith("about:blank") or "://" not in action:
                sfh_flag = 1
                break

        # ✅ Feature dictionary
        features = {
            "UsingIP": ip_flag,
            "LongURL": long_url_flag,
            "ShortURL": short_url_flag,
            "Symbol@": symbol_flag,
            "Redirecting//": redirect_flag,
            "PrefixSuffix-": prefix_flag,
            "SubDomains": subdomain_count,
            "HTTPS": https_flag,
            "DomainRegLen": domain_age_flag,
            "Favicon": favicon_flag,
            "NonStdPort": port_flag,
            "HTTPSDomainURL": https_domain_flag,
            "RequestURL": request_url_flag,
            "AnchorURL": anchor_url_flag,
            "LinksInScriptTags": script_links_flag,
            "ServerFormHandler": sfh_flag
        }

        print("✅ Extracted features:", features)  # <--- log features
        driver.quit()
        return features

    except Exception as e:
        print("❌ Error extracting features:", e)
        return None
