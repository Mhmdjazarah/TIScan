import pytest

from tiscan.ioc import defang, detect, extract, refang, registered_domain


@pytest.mark.parametrize("raw, kind, value", [
    ("8.8.8.8", "ip", "8.8.8.8"),
    ("185.220.101.1:443", "ip", "185.220.101.1"),
    ("[2001:db8::1]", "ip", "2001:db8::1"),
    ("EXAMPLE.com", "domain", "example.com"),
    ("evil[.]com", "domain", "evil.com"),
    ("hxxps://evil[.]com/login?x=1", "url", "https://evil.com/login?x=1"),
    ("evil.com/payload.exe", "url", "http://evil.com/payload.exe"),
    ("44D88612FEA8A8F36DE82E1278ABB02F", "md5", "44d88612fea8a8f36de82e1278abb02f"),
    ("3395856ce81f2b7382dee72602f798b642f14140", "sha1", "3395856ce81f2b7382dee72602f798b642f14140"),
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha256",
     "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
    ("Alice[@]Corp[.]com", "email", "alice@corp.com"),
])
def test_detect(raw, kind, value):
    ioc = detect(raw)
    assert (ioc.type, ioc.value) == (kind, value)


def test_private_ip_is_flagged():
    assert detect("10.1.2.3").private
    assert detect("http://192.168.1.1/admin").private
    assert not detect("1.1.1.1").private


def test_keyword_only_when_allowed():
    with pytest.raises(ValueError):
        detect("Acme Holding")
    assert detect("Acme Holding", allow_keyword=True).type == "keyword"


def test_refang_and_defang_roundtrip():
    assert refang("hxxp://bad[.]site[.]com") == "http://bad.site.com"
    assert defang("http://bad.com/a", "url") == "hxxp[://]bad[.]com/a"
    assert defang("1.2.3.4", "ip") == "1[.]2[.]3[.]4"


@pytest.mark.parametrize("host, apex", [
    ("a.b.example.com", "example.com"),
    ("www.bank.com.jo", "bank.com.jo"),
    ("mail.gov.sa", "mail.gov.sa"),
    ("portal.moh.gov.sa", "moh.gov.sa"),
    ("example.co.uk", "example.co.uk"),
])
def test_registered_domain(host, apex):
    assert registered_domain(host) == apex


def test_extract_from_phishing_email():
    text = """
    Received: from mail.badhost.ru (unknown [10.0.0.5]) by mx.corp.com
    Received: from [185.220.101.1]
    From: "IT Support" <support[@]micros0ft-login[.]com>
    Please verify at hxxps://micros0ft-login[.]com/verify.php?id=1 or open invoice.pdf / readme.md
    Payload: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    Time 10:20:30, version 1.2.3.4.5
    """
    found = {(i["type"], i["value"]) for i in extract(text)}
    assert ("url", "https://micros0ft-login.com/verify.php?id=1") in found
    assert ("email", "support@micros0ft-login.com") in found
    assert ("ip", "185.220.101.1") in found
    assert ("ip", "10.0.0.5") in found
    assert ("sha256", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") in found
    assert ("domain", "mail.badhost.ru") in found
    values = {v for _, v in found}
    assert "invoice.pdf" not in values and "readme.md" not in values
    assert not any(t == "ip" and v.startswith("1.2.3") for t, v in found)
    private = {i["value"]: i["private"] for i in extract(text) if i["type"] == "ip"}
    assert private["10.0.0.5"] is True and private["185.220.101.1"] is False
