import pytest
from cyberswarm.agents.secrets import scan_text, entropy, is_placeholder
def ids(t): return [c for c, *_ in scan_text(t)]
@pytest.mark.parametrize("line,cid", [
    ('-----BEGIN RSA PRIVATE KEY-----', "secret.private_key"), ('-----BEGIN OPENSSH PRIVATE KEY-----', "secret.private_key"),
    ('k = "AKIAABCDEFGHIJKLMNOP"', "secret.aws_key"), ('t = "ghp_' + "a1B2" * 9 + '"', "secret.github_token"),
    ('s = "xoxb-123456789012-abcdefABCDEF"', "secret.slack_token"), ('g = "AIza' + "B" * 35 + '"', "secret.google_api_key"),
    ('j = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlX2hlcmU"', "secret.jwt"),
    ('db_password = "hunter2xx"', "secret.assignment"), ('"api_token": "abcdef12"', "secret.assignment"), ('apikey="zq8Lm2pX"', "secret.assignment"),
    ('salt = "q9Z3vT7mK2pX8wR4nB6yH1cJ5fL0dG"', "secret.high_entropy")])
def test_detects(line, cid): assert ids(line) == [cid]
@pytest.mark.parametrize("line", ['password = "changeme"', 'API_KEY = "your_api_key_here"', 'token = "example-token-xxxxxxxx"',
    'password = "${DB_PASSWORD}"', 'secret = "{{ vault.secret }}"', 'password = var.db_pass', 'name = "password"',
    'sha = "d41d8cd98f00b204e9800998ecf8427e"', 'id = "123e4567-e89b-12d3-a456-426614174000"', 'msg = "aaaaaaaaaaaaaaaaaaaaaaaa"',
    'title = "This_is_a_long_ordinary_identifier"', 'pw = os.environ["DB_PASSWORD_VALUE"]'])
def test_no_false_positive(line): assert ids(line) == []
def test_specific_wins_over_assignment(): assert ids('GITHUB_TOKEN = "ghp_' + "a1B2" * 9 + '"') == ["secret.github_token"]
def test_masked_line():
    (_, n, v, masked), = scan_text('x\npassword = "hunter2xx"')
    assert n == 2 and "hunter2xx" not in masked and "hunt****" in masked
def test_entropy_threshold(): assert entropy("aaaa") == 0 and entropy("q9Z3vT7mK2pX8wR4nB6yH1cJ5fL0dG") > 4.0 and is_placeholder("xxxxxxxx")
