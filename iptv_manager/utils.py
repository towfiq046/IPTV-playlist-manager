from urllib.parse import urlparse


def get_domain_from_url(url: str) -> str | None:
    """Extracts the network location (domain) from a URL."""
    try:
        return urlparse(url.strip()).netloc
    except (ValueError, AttributeError):
        return None
