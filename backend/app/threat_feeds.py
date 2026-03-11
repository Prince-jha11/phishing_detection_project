import requests
from urllib.parse import urlparse

BAD_DOMAINS = set()
BAD_URLS = set()

# store which feed reported the domain
THREAT_SOURCES = {}


def normalize_domain(value):

    try:
        if not value.startswith(("http://", "https://")):
            value = "http://" + value

        domain = urlparse(value).netloc.lower().replace("www.", "")
        return domain

    except:
        return None


def statistical_report(url):

    domain = normalize_domain(url)

    if not domain:
        return 1, None

    url_lower = url.lower()

    # check full URL match
    if url_lower in BAD_URLS:
        source = THREAT_SOURCES.get(domain, "Threat Feed")
        return -1, source

    # check domain matches
    for bad in BAD_DOMAINS:

        if domain == bad or domain.endswith("." + bad):
            source = THREAT_SOURCES.get(bad, "Threat Feed")
            return -1, source

    return 1, None


def load_threat_feeds():

    global BAD_DOMAINS, BAD_URLS, THREAT_SOURCES

    if BAD_DOMAINS:
        return

    text_feeds = [
        "https://openphish.com/feed.txt",
        "https://phishing.army/download/phishing_army_blocklist.txt",
        "https://urlhaus.abuse.ch/downloads/text/",
        "https://www.spamhaus.org/drop/drop.txt"
    ]

    for feed_url in text_feeds:

        try:

            r = requests.get(feed_url, timeout=15)

            for line in r.text.splitlines():

                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                line = line.split()[0]

                BAD_URLS.add(line.lower())

                domain = normalize_domain(line)

                if domain:
                    BAD_DOMAINS.add(domain)

                    # store which feed reported it
                    THREAT_SOURCES[domain] = feed_url

        except Exception as e:
            print("Feed load failed:", feed_url, e)

    # -------- PHISHTANK --------

    try:

        r = requests.get(
            "https://data.phishtank.com/data/online-valid.json",
            timeout=20
        )

        data = r.json()

        for entry in data:

            phishing_url = entry.get("url")

            if phishing_url:

                BAD_URLS.add(phishing_url.lower())

                domain = normalize_domain(phishing_url)

                if domain:
                    BAD_DOMAINS.add(domain)

                    THREAT_SOURCES[domain] = "PhishTank"

    except Exception as e:
        print("PhishTank load failed:", e)

    print("Threat feeds loaded:", len(BAD_DOMAINS), "domains")