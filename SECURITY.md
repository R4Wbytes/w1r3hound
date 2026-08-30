# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| < 2.0   | No        |

## Reporting a vulnerability

If you discover a security vulnerability in w1r3hound, please report it
responsibly via [GitHub Security Advisories](https://github.com/R4Wbytes/w1r3hound/security/advisories/new).

Do **not** open a public issue for security vulnerabilities.

### Expected response

- Acknowledgement within 48 hours.
- Status update within 7 days.
- Fix or mitigation within 30 days for confirmed vulnerabilities.

## Scope

w1r3hound is an offensive reconnaissance tool intended for authorized security
testing. The following are **in scope** for security reports:

- Vulnerabilities in the Web GUI (XSS, CSRF bypass, authentication bypass, privilege escalation)
- Command injection via user-controlled input
- Path traversal in report/wordlist handling
- Information disclosure of credentials or session tokens
- SSRF via the scanning engine when `--block-private-egress` is enabled

The following are **out of scope**:

- The tool's intended ability to perform reconnaissance against authorized targets
- Findings in scan results produced by the tool
- Social engineering attacks against users of the tool
