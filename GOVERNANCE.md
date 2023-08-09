# cert-manager Governance (proposal)

This document defines project governance for the cert-manager project.

## Contributors

cert-manager is for everyone. Anyone can become a cert-manager contributor
simply by contributing to the project, whether through code, documentation, blog
posts, community management, or other means. As with all cert-manager community
members, contributors are expected to follow the [cert-manager Code of
Conduct][coc].

All contributions to cert-manager code, documentation, or other components in
the cert-manager GitHub org must follow the guidelines in [the contributing
page][contrib]. Whether these contributions are merged into the project is the
prerogative of the maintainers.

## Maintainers

Maintainers have the ability to merge code into the project. Anyone can become a
cert-manager maintainer (see "Becoming a maintainer" below.)

> **Note:** In some CNCF projects, a difference is made between a "committer"
> and a "maintainer" (cf. [committer-vs-maintainer][]). In the context of the
> cert-manager project, committer and maintainer are the same. We will be using
> the term "maintainer" throughout this document.

[committer-vs-maintainer]: https://github.com/cncf/toc/pull/876#issuecomment-1189399941

The cert-manager maintainers are:

- James Munnelly (@munnerz)
- Josh van Leeuwen (@joshvanl)
- Richard Wall (@wallrj)
- Jake Sanders (@jakexks)
- Maël Valais (@maelvls)
- Irbe Krumina (@irbekrm)
- Ashley Davis (@sgtcodfish)
- Tim Ramlot (@inteon)

This list is reflected in `OWNERS.md` files present at the root of the projects
within the cert-manager organization.

### Maintainers Responsibilities

cert-manager maintainers are expected to:

- Review pull requests, triage issues, and fix bugs in their areas of expertise,
  ensuring that all changes go through the project's code review and integration
  processes.
- Monitor cncf-cert-manager-\* emails and the cert-manager-dev and
  cert-manager-dev channels on Slack, and help out when possible.
- Rapidly respond to any time-sensitive security release processes.
- Attend meetings with the cert-manager Steering Committee.

### Maintainer Decision-Making

Ideally, all project decisions are resolved by maintainer consensus. If this is
not possible, maintainers may call a vote. The voting process is a simple
majority in which each maintainer receives one vote.

### Becoming a Maintainer

Anyone can become a cert-manager maintainer. Maintainers should be proficient in
Go; have expertise in at least one of the domains (Kubernetes, PKI, ACME); have
the time and ability to meet the maintainer expectations above; and demonstrate
the ability to work with the existing maintainers and project processes.

To become a maintainer, start by expressing interest to existing maintainers.
Existing maintainers will then ask you to demonstrate the qualifications above
by contributing PRs, doing code reviews, and other such tasks under their
guidance. After several months of working together, maintainers will decide
whether to grant maintainer status.

### Stepping Down as a Maintainer

If a maintainer is no longer interested in or cannot perform the duties listed
above, they should move themselves to emeritus status. If necessary, this can
also occur through the decision-making process outlined above.

A review of the OWNERS file is performed every year by the current maintainers.
During this review, the maintainers that have not been active in the last year
are asked whether they would like to become an emeritus maintainer.

[coc]: https://github.com/cert-manager/cert-manager/blob/master/CODE_OF_CONDUCT.md
[contrib]: https://cert-manager.io/docs/contributing/

### Emeriti Maintainers

Former maintainers include:

- Maartje Eyskens (@meyskens)
- Joakim Ahrlin (@jahrlin)
