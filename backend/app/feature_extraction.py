import re
import ssl
import socket
import csv
import requests
import tldextract
import whois

from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from app.threat_feeds import statistical_report


class FeatureExtraction:

    def extract_all_features(self, url):

        features = {}

        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return {}

        ext = tldextract.extract(url)

        # ---------------- URL STRUCTURE ----------------

        ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
        features["having_IP_Address"] = -1 if re.search(ip_pattern, url) else 1

        length = len(url)
        if length < 54:
            features["URL_Length"] = 1
        elif length <= 75:
            features["URL_Length"] = 0
        else:
            features["URL_Length"] = -1

        shorteners = ["bit.ly","goo.gl","tinyurl.com","t.co","ow.ly"]
        features["Shortining_Service"] = -1 if any(s in url for s in shorteners) else 1

        features["having_At_Symbol"] = -1 if "@" in url else 1

        features["double_slash_redirecting"] = -1 if url.find("//",7) != -1 else 1

        features["Prefix_Suffix"] = -1 if "-" in ext.domain else 1

        sub = ext.subdomain
        if sub.count('.') == 0:
            features["having_Sub_Domain"] = 1
        elif sub.count('.') == 1:
            features["having_Sub_Domain"] = 0
        else:
            features["having_Sub_Domain"] = -1

        # ---------------- SSL ----------------

        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname,443),timeout=5) as sock:
                with context.wrap_socket(sock,server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            issuer = dict(x[0] for x in cert['issuer'])
            issuer_name = issuer.get('organizationName','')

            trusted = [
    "DigiCert",
    "Let's Encrypt",
    "GlobalSign",
    "Sectigo",
    "GoDaddy",

    "Entrust",
    "Comodo",  # legacy name (Sectigo)
    "GeoTrust",
    "Thawte",
    "RapidSSL",

    "Amazon",
    "Google Trust Services",
    "Microsoft",
    "Cloudflare",

    "SSL.com",
    "IdenTrust",
    "Buypass",
    "Actalis",

    "Trustwave",
    "Certum",
    "SecureTrust",
    "Network Solutions",

    "QuoVadis",
    "Starfield",   # GoDaddy subsidiary
    "Cybertrust"
]

            features["SSLfinal_State"] = 1 if any(t in issuer_name for t in trusted) else 0

        except:
            features["SSLfinal_State"] = -1

        # ---------------- WHOIS ----------------

        w = None

        try:
            w = whois.whois(hostname)

            expiration = w.expiration_date
            if isinstance(expiration,list):
                expiration = expiration[0]

            if expiration:
                remaining = (expiration - datetime.now()).days
                features["Domain_registeration_length"] = 1 if remaining >=365 else -1
            else:
                features["Domain_registeration_length"] = -1

        except:
            features["Domain_registeration_length"] = -1

        # ---------------- PORT ----------------

        features["port"] = 1 if parsed.port in [None,80,443] else -1

        # ---------------- HTTPS TOKEN ----------------

        features["HTTPS_token"] = -1 if "https" in hostname.replace("https","") else 1

        # ---------------- PAGE CONTENT ----------------

        try:
            response = requests.get(url,timeout=5,headers={"User-Agent":"Mozilla/5.0"})
            soup = BeautifulSoup(response.text,"html.parser")
        except:
            soup = None

        if soup:

            domain = hostname

            # Request URL
            total=0
            suspicious=0

            for tag in soup.find_all(['img','audio','embed','iframe']):
                src=tag.get("src")

                if src:
                    total+=1
                    if src.startswith("http") and domain not in src:
                        suspicious+=1

            if total==0:
                features["Request_URL"]=1
            else:
                ratio=suspicious/total
                features["Request_URL"]=1 if ratio<0.22 else 0 if ratio<=0.61 else -1

            # URL of Anchor
            anchors=soup.find_all("a")
            total=len(anchors)
            suspicious=0

            for a in anchors:
                href=a.get("href")

                if href and ((href.startswith("http") and domain not in href) or "#" in href):
                    suspicious+=1

            if total==0:
                features["URL_of_Anchor"]=1
            else:
                ratio=suspicious/total
                features["URL_of_Anchor"]=1 if ratio<0.31 else 0 if ratio<=0.67 else -1

            # Links in tags
            meta=soup.find_all("meta")
            link=soup.find_all("link")
            script=soup.find_all("script")

            total=len(meta)+len(link)+len(script)
            suspicious=0

            for tag in meta+link+script:
                src=tag.get("href") or tag.get("src")

                if src and src.startswith("http") and domain not in src:
                    suspicious+=1

            if total==0:
                features["Links_in_tags"]=1
            else:
                ratio=suspicious/total
                features["Links_in_tags"]=1 if ratio<0.17 else 0 if ratio<=0.81 else -1

            # SFH
            forms=soup.find_all("form")
            suspicious=False

            for form in forms:
                action=form.get("action")

                if not action or (action.startswith("http") and domain not in action):
                    suspicious=True

            features["SFH"]=-1 if suspicious else 1

            # Submitting to email
            email_forms=soup.find_all("form",action=lambda x:x and "mailto:" in x)
            features["Submitting_to_email"]=-1 if email_forms else 1

            # Abnormal URL
            features["Abnormal_URL"]=1 if hostname in url else -1

            # Redirect
            features["Redirect"]=1 if len(response.history)<=1 else 0 if len(response.history)<=3 else -1

            # Mouseover
            features["on_mouseover"]=-1 if "onmouseover" in response.text.lower() else 1

            # Right click
            features["RightClick"]=-1 if "event.button==2" in response.text else 1

            # Popup
            features["popUpWidnow"]=-1 if "alert(" in response.text.lower() else 1

            # Iframe
            features["Iframe"]=-1 if soup.find_all("iframe") else 1

        else:

            features.update({
                "Request_URL":-1,
                "URL_of_Anchor":-1,
                "Links_in_tags":-1,
                "SFH":-1,
                "Submitting_to_email":-1,
                "Abnormal_URL":-1,
                "Redirect":-1,
                "on_mouseover":-1,
                "RightClick":-1,
                "popUpWidnow":-1,
                "Iframe":-1
            })

        # ---------------- DOMAIN AGE ----------------

        # ---------------- DOMAIN AGE ----------------

        try:
            if w and w.creation_date:

                creation = w.creation_date

                # handle list
                if isinstance(creation, list):
                    creation = next((d for d in creation if isinstance(d, datetime)), None)

                if isinstance(creation, datetime):
                    age_days = (datetime.now() - creation).days

                    # store BOTH values
                    features["age_of_domain"] = 1 if age_days >= 365 else -1
                    features["domain_age_days"] = age_days

                else:
                    features["age_of_domain"] = -1
                    features["domain_age_days"] = None

            else:
                features["age_of_domain"] = -1
                features["domain_age_days"] = None

        except:
            features["age_of_domain"] = -1
            features["domain_age_days"] = None

        # ---------------- DNS ----------------

        try:
            socket.gethostbyname(hostname)
            features["DNSRecord"]=1
        except:
            features["DNSRecord"]=-1

        # ---------------- WEB TRAFFIC ----------------

        try:

            rank=None

            with open("tranco.csv") as f:
                reader=csv.reader(f)

                for r,site in reader:
                    if site==hostname:
                        rank=int(r)
                        break

            if rank and rank<100000:
                features["web_traffic"]=1
            elif rank:
                features["web_traffic"]=0
            else:
                features["web_traffic"]=-1

        except:
            features["web_traffic"]=-1

        # ---------------- GOOGLE INDEX ----------------

        try:

            query=f"https://www.google.com/search?q=site:{hostname}"
            r=requests.get(query,headers={"User-Agent":"Mozilla/5.0"})

            features["Google_Index"]=-1 if "did not match any documents" in r.text else 1

        except:
            features["Google_Index"]=-1

        # ---------------- STATISTICAL REPORT ----------------

        stat_value, threat_source = statistical_report(url)

        features["Statistical_report"] = stat_value

        # extra info for UI
        features["Threat_Source"] = threat_source

        return features