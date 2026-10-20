from minisiem.parsers import decode_path, parse_nginx_line, parse_syslog_line


def p(line, year=2026):
    return parse_syslog_line(line, "auth", year)


def test_ssh_failed_password_for_valid_user():
    ev = p(
        "Oct 18 01:02:03 web01 sshd[812]: Failed password for root from 203.0.113.5 port 5 ssh2"
    )
    assert (ev["action"], ev["outcome"], ev["user"], ev["src_ip"]) == (
        "login",
        "failure",
        "root",
        "203.0.113.5",
    )
    assert ev["ts"] == "2026-10-18T01:02:03Z"
    assert ev["host"] == "web01" and ev["program"] == "sshd" and ev["pid"] == 812


def test_ssh_failed_for_invalid_user_keeps_the_name():
    ev = p(
        "Oct 18 01:02:03 web01 sshd[1]: Failed password for invalid user oracle from 1.2.3.4 port 9 ssh2"
    )
    assert ev["user"] == "oracle" and ev["outcome"] == "failure"


def test_ssh_accepted_and_invalid_user_lines():
    ok = p(
        "Oct 18 01:02:03 web01 sshd[1]: Accepted publickey for alice from 10.0.0.7 port 9 ssh2"
    )
    assert (ok["action"], ok["outcome"], ok["user"]) == ("login", "success", "alice")
    bad = p("Oct 18 01:02:03 web01 sshd[1]: Invalid user test from 1.2.3.4 port 9")
    assert (bad["action"], bad["user"], bad["src_ip"]) == (
        "invalid_user",
        "test",
        "1.2.3.4",
    )


def test_sudo_command_and_failure():
    ok = p(
        "Oct 18 01:02:03 web01 sudo[7]:   deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash -l"
    )
    assert (ok["action"], ok["user"], ok["command"]) == (
        "sudo",
        "deploy",
        "/bin/bash -l",
    )
    bad = p(
        "Oct 18 01:02:03 web01 sudo[7]:   deploy : 3 incorrect password attempts ; TTY=pts/0 ; COMMAND=/bin/ls"
    )
    assert (bad["action"], bad["outcome"]) == ("sudo", "failure")


def test_su_useradd_crontab_cron():
    assert (
        p("Oct 18 01:02:03 h su[1]: FAILED SU (to root) www-data on pts/1")["action"]
        == "su"
    )
    assert (
        p("Oct 18 01:02:03 h useradd[1]: new user: name=support, UID=1002")["user"]
        == "support"
    )
    assert (
        p("Oct 18 01:02:03 h crontab[1]: (bob) REPLACE (bob)")["action"]
        == "cron_change"
    )
    assert p("Oct 18 01:02:03 h CRON[1]: (root) CMD (/x.sh)")["action"] == "cron_exec"
    assert p("Oct 18 01:02:03 h crontab[1]: (bob) LIST (bob)")["action"] == "other"


def test_iso_timestamps_with_offset_are_converted_to_utc():
    ev = p(
        "2026-10-18T03:02:03+02:00 web01 sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2"
    )
    assert ev["ts"] == "2026-10-18T01:02:03Z"


def test_unparsable_lines_return_none():
    assert p("not a log line") is None
    assert p("Foo 99 25:61:61 h x[1]: y") is None


def test_single_digit_day_with_padding():
    assert p("Oct  8 01:02:03 h sshd[1]: hi")["ts"] == "2026-10-08T01:02:03Z"


NGINX = (
    '203.0.113.9 - bob [18/Oct/2026:12:00:01 +0200] "GET /a b?x=1%27 HTTP/1.1" '
    '404 -  "-" "curl/8.0"'
)


def test_nginx_line_fields():
    ev = parse_nginx_line(NGINX.replace("-  ", "- "))
    assert ev["ts"] == "2026-10-18T10:00:01Z"  # +0200 converted to UTC
    assert ev["src_ip"] == "203.0.113.9" and ev["user"] == "bob"
    assert ev["http_method"] == "GET" and ev["http_status"] == 404
    assert ev["http_path"] == "/a b?x=1'" and ev["http_bytes"] is None
    assert ev["outcome"] == "failure" and ev["user_agent"] == "curl/8.0"


def test_nginx_dash_user_is_null_and_success_outcome():
    line = '1.2.3.4 - - [18/Oct/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 12 "-" "UA"'
    ev = parse_nginx_line(line)
    assert ev["user"] is None and ev["outcome"] == "success" and ev["http_bytes"] == 12


def test_decode_path_handles_double_encoding_and_plus():
    assert decode_path("/d?f=%252e%252e%252fx") == "/d?f=../x"
    assert decode_path("/s?q=a+b") == "/s?q=a b"


def test_cmdaudit_line_becomes_command_event():
    line = (
        "Oct 20 12:00:01 victim cmdaudit[901]: "
        "user=labuser src=10.77.0.50 cmd=cat /etc/passwd"
    )
    ev = parse_syslog_line(line, "auth", 2026)
    assert ev["action"] == "command"
    assert ev["user"] == "labuser"
    assert ev["src_ip"] == "10.77.0.50"
    assert ev["command"] == "cat /etc/passwd"
