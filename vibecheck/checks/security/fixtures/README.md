# Security check fixtures

`sample-app/` is a tiny app that is insecure on purpose, used by
`tests/test_framework.py` to check the security plugin reports exactly what
the scanner always has. It holds no key-shaped strings, so secret scanners
have nothing to trip on; the secret rules are covered by the scanner's own
tests.
