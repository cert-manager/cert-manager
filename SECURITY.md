# Vulnerability Reporting Process

Security is the number one priority for cert-manager. If you think you've found a
security vulnerability in a cert-manager project, you're in the right place.

Our reporting procedure is a work-in-progress, and will evolve over time. We
welcome advice, feedback and pull requests for improving our security
reporting processes.

## Covered Repositories and Issues

When we say "a security vulnerability in cert-manager" we mean a security issue
in any repository under the [cert-manger GitHub organization](https://github.com/cert-manager/).

This reporting process is intended only for security issues in the cert-manager
project itself, and doesn't apply to applications _using_ cert-manager or to
issues which do not affect security.

Broadly speaking, if the issue cannot be fixed by a change to one of the covered
repositories above, then it might not be appropriate to use this reporting
mechanism and a GitHub issue in the appropriate repo or a question in Slack
might be a better choice.

All that said, **if you're unsure** please reach out using this process before
raising your issue through another channel. We'd rather err on the side of
caution!

## Security Contacts

The people who should have access to read your security report are listed in
[`SECURITY_CONTACTS.md`](./SECURITY_CONTACTS.md)

## Reporting Process

1. Describe the issue in English, ideally with some example configuration or
   code which allows the issue to be reproduced. Explain why you believe this
   to be a security issue in cert-manager, if that's not obvious.
2. Put that information into an email. Use a descriptive title.
3. Send the email to [`cert-manager-security@googlegroups.com`](mailto:cert-manager-security@googlegroups.com)

## Response

Response times could be affected by weekends, holidays, breaks or time zone
differences. That said, the security response team will endeavour to reply as
soon as possible, ideally within 3 working days.

If the team concludes that the reported issue is indeed a security
vulnerability in a cert-manager project, at least two members of the security
response team will discuss the next steps together as soon as possible, ideally
within 24 hours.

As soon as the team decides that the report is of a genuine vulnerability,
one of the team will respond to the reporter acknowledging the issue and
establishing a disclosure timeline, which should be as soon as possible.
