# Security policy

Email-Verifier is intended for consent-based deliverability checks. It does not send messages or bypass provider protections. Operators should throttle requests, avoid probing arbitrary personal addresses, protect input and result files, and follow applicable law and provider terms.

Do not commit credentials, private email lists, `.env` files, or live SMTP secrets. The CLI does not log sender credentials or raw result lists by default.

To report a security vulnerability, open a private report with the repository maintainers rather than publishing exploit details in an issue. Include the affected version, a minimal reproduction, impact, and any safe mitigation.
