from aegis.plugins.builtin.service.plugin import identify_service

def test_identify_ssh():
    result = identify_service(22)

    assert result["service_name"] == "ssh"
    assert result["tls"] is False

def test_identify_http():
    result = identify_service(80)

    assert result["service_name"] == "http"
    assert result["tls"] is False

def test_identify_https():
    result = identify_service(443)

    assert result["service_name"] == "https"
    assert result["tls"] is True

def test_identify_unknown_service():
    result = identify_service(12345)

    assert result["service_name"] == "unknown"
    assert result["tls"] is False