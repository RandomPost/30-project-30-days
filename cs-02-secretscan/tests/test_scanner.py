from secretscan.rules import shannon_entropy
from secretscan.scanner import scan_text


def rules(text):
    return {f.rule for f in scan_text(text)}


def test_aws_access_key(aws_key):
    assert rules(f"id = {aws_key}") == {"aws-access-key-id"}


def test_aws_secret_assignment():
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "q9d8s7f6g5"
    assert "aws-secret-access-key" in rules(f'aws_secret_access_key = "{secret}"')


def test_private_key(private_key_header):
    assert rules(private_key_header) == {"private-key"}


def test_github_token(github_token):
    assert rules(f"export T={github_token}") == {"github-token"}


def test_generic_assignment_not_double_reported_as_entropy(entropy_string):
    found = scan_text(f'api_key = "{entropy_string}"')
    assert [f.rule for f in found] == ["generic-api-key"]


def test_high_entropy_string_alone(entropy_string):
    assert rules(f'blob = "{entropy_string}"') == {"high-entropy-string"}


def test_clean_code_and_placeholders_pass():
    assert scan_text("x = 1\nname = 'hello world'\n") == []
    assert scan_text('api_key = "your_api_key_goes_here"') == []
    assert scan_text('token = "xxxxxxxxxxxxxxxxxxxxxxxx"') == []


def test_inline_ignore_marker(aws_key):
    assert scan_text(f"id = {aws_key}  # secretscan:ignore") == []


def test_line_numbers_and_redaction(aws_key):
    (f,) = scan_text(f"a\nb\nid = {aws_key}\n", "x.py")
    assert (f.path, f.line) == ("x.py", 3)
    assert aws_key not in f.redacted


def test_entropy_ordering():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcdefgh") > shannon_entropy("aabbccdd")
