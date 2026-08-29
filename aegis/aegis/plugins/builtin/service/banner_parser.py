import re

OPENSSH_PATTERN = re.compile(
    r"OpenSSH[_/-]([0-9][A-Za-z0-9._-]*)",
    re.IGNORECASE,
)

NGINX_PATTERN = re.compile(
    r"nginx/([0-9][A-Za-z0-9._-]*)",
    re.IGNORECASE,
)

APACHE_PATTERN = re.compile(
    r"Apache/([0-9][A-Za-z0-9._-]*)",
    re.IGNORECASE,
)

def parse_banner(
    banner: str | None,
) -> dict[str, str | None]:
    result = {
        "product": None,
        "version": None,
    }

    if not banner:
        return result

    match = OPENSSH_PATTERN.search(banner)

    if match:
        return {
            "product": "OpenSSH",
            "version": match.group(1),
        }

    match = NGINX_PATTERN.search(banner)

    if match:
        return {
            "product": "nginx",
            "version": match.group(1),
        }

    match = APACHE_PATTERN.search(banner)

    if match:
        return {
            "product": "Apache",
            "version": match.group(1),
        }

    return result