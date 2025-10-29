from urllib.parse import urlparse


def get_domain_from_url(url: str) -> str | None:
    """
    Extracts the network location (domain) from a URL.
    Handles special cases like CORS proxy URLs for more accurate domain checking.
    """
    try:
        # If a URL is embedded within another (e.g., a proxy), find the last one.
        if "https://" in url and url.rfind("https://") > 0:
            url = url[url.rfind("https://") :]
        elif "http://" in url and url.rfind("http://") > 0:
            url = url[url.rfind("http://") :]

        return urlparse(url.strip()).netloc
    except (ValueError, AttributeError):
        return None
