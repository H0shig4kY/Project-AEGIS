from aegis.plugins.builtin.service.banner_parser import (
    parse_banner,
)


def test_parse_openssh_banner():
    result = parse_banner(
        "SSH-2.0-OpenSSH_9.6"
    )

    assert result["product"] == "OpenSSH"
    assert result["version"] == "9.6"


def test_parse_nginx_banner():
    result = parse_banner(
        "Server: nginx/1.26.1"
    )

    assert result["product"] == "nginx"
    assert result["version"] == "1.26.1"


def test_parse_apache_banner():
    result = parse_banner(
        "Server: Apache/2.4.62"
    )

    assert result["product"] == "Apache"
    assert result["version"] == "2.4.62"


def test_parse_unknown_banner():
    result = parse_banner(
        "SOME-RANDOM-SERVICE"
    )

    assert result["product"] is None
    assert result["version"] is None


def test_parse_none_banner():
    result = parse_banner(None)

    assert result["product"] is None
    assert result["version"] is None