
# cert-manager Governance

This document defines project governance for the cert-manager project. Its
purpose is to describe how decisions are made on the project and how anyone can
influence these decisions. We have six levels of responsability, each one
building on the previous:

- Contributor,
- GitHub Member,
- Reviewer,
- Approver,
- Maintainer,
- Admin.

## Contributors

cert-manager is for everyone. Anyone can become a cert-manager contributor
simply by contributing to the project, whether through code, documentation, blog
posts, community management, or other means. As with all cert-manager community
members, contributors are expected to follow the [cert-manager Code of
Conduct][coc].

All contributions to cert-manager code, documentation, or other components in
the cert-manager GitHub org must follow the guidelines in [the contributing
page][contrib]. Whether these contributions are merged into the project is the
prerogative of the reviewers, approvers and/or maintainers.

## GitHub Members

GitHub Members are active contributors to the cert-manager project.

A contributor is considered to be active when they have had at least one
interaction (comment on an issue or PR or message in the #cert-manager or #cert-
manager-dev channels) within the last 18 months.

Members that have been inactive over the past 18 months may be removed from the
GitHub organization.

### Becoming a GitHub Member

To be added as a GitHub member of the cert-manager organization, you will need
to look for two sponsors with at least the `reviewer` role. These two sponsors
must have had some meaningful interaction with you on an issue on GitHub or on
the cert-manager or cert-manager-dev channels on Slack.

Then, open an issue on the `cert-manager/cert-manager` repository and mention
the sponsors as well as links to the meaningful interations (Slack threads,
GitHub issues). Ask your sponsors to confirm their sponsorship by commenting on
your PR. After that, your request will be reviewed by a cert-manager admin, in
accordance with their SLO.

To be added as a GitHub member, you will also need to enable [two-factor authentication][] on your GitHub account.

GitHub members are encouraged to engage with the [cert-manager-dev][] mailing list as well as the [cert-manager](https://kubernetes.slack.com/messages/cert-manager) and [cert-manager-dev](https://kubernetes.slack.com/messages/cert-manager-dev) Slack channels.

[two-factor authentication]: https://help.github.com/articles/about-two-factor-authentication
[cert-manager-dev]: https://groups.google.com/forum/#!forum/cert-manager-dev

## Reviewers

The mission of the reviewer is to read through PRs for quality and correctness
on all or some part of cert-manager. Reviewers are knowledgeable about the
codebase as well as software engineering principles. Reviewers are defined in
the file [`OWNERS`](./OWNERS).

### Becoming a Reviewer

To become a reviewer, you will need to look for a sponsor with at least the
`approver` role. Then, create a PR to add your name to the list of `reviewers`
in the `OWNERS` file. The PR description should list your significant
contributions.

Your sponsor must have the approver role. Your sponsor must have had close
interactions with you: he must have been closely reviewed one of your PRs or
worked with you on a thorny issue. The sponsor is expected to give his approval
as a comment on the `OWNERS` PR. Additionally, your `OWNERS` PR should list your
substantial contributions to the project.

### Responsibilities

- When possible, review pull requests, triage issues, and fix bugs in their
  areas of expertise.
- Ensure that all changes go through the project's code review and integration
  processes.

### Privileges

- Able to `/lgtm` on pull requests.

## Approver

> **Note:** some projects call this role "committer".

As an approver, your role is to make sure the right people reviewed the PRs. The
approver's focus isn't to review the code; instead, they put a stamp of approval
on an existing review with the command `/approve`. Note that it is always
possible to review a PR as an approver with `/lgtm`, in which case the PR will
be automatically approved.

Approvers are defined under the `approver` section in the
[`OWNERS`](./OWNERS) file.

### Becoming an Approver

To become an approver and start merging PRs, you must have reviewed 5 PRs.

You will then need to get sponsorship from one of the maintainers. The
maintainer sponsoring you must have had close work interactions with you and be
knowledgeable of some of your work. 

To apply, open a PR to update the `OWNERS` file and mention your sponsor in the
description. The PR description should also list the PRs you have reviewed.

### Responsibilities

- Expected to be responsive to review requests.
- Stay up to date with the project's direction and goals,
  e.g., by attending some of the bi-weekly meetings, standups,
  or being around in the cert-manager-dev Slack channel.

### Privileges

- Can `/approve` on pull requests.

## Maintainer

A maintainer is someone who can communicate with the CNCF on behalf of the
project and who can participate in a maintainers vote. The list of maintainers
is available in the file [`MAINTAINERS.md`](./MAINTAINERS.md).

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

### Privileges

- Can communicate with the CNCF on behalf of the project.
- Can participate in a "maintainers vote".

### Responsibilities

- Monitor cncf-cert-manager-\* emails and help out when possible.
- Respond to time-sensitive security release processes.
- Attend meetings with the cert-manager Steering Committee.
- Attend "maintainers vote" meetings when one is scheduled.

### Maintainer Decision-Making (maintainers vote)

Substantial changes to the project, require a "maintainers vote". This includes,
but is not limited to, changes to the project's roadmap, changes to the project's
scope, fundamental design decisions, and changes to the project's governance. 

A maintainer vote is a simple majority in which each maintainer receives one vote.

### Stepping Down as a Maintainer

If a maintainer is no longer interested in or cannot perform the duties listed
above, they should move themselves to emeritus status. If necessary, this can
also occur through the decision-making process outlined above.

A review of the [`MAINTAINERS.md`](./MAINTAINERS.md) file is performed every
year by the current maintainers. During this review, the maintainers that have
not been active in the last 18 months are asked whether they would like to
become an emeritus maintainer, they are expected to respond within 30 days. If
they do not respond, they will automatically be moved to emeritus status.

[coc]: https://github.com/cert-manager/cert-manager/blob/master/CODE_OF_CONDUCT.md
[contrib]: https://cert-manager.io/docs/contributing/

## Admin

An admin is a maintainer who has admin privileges on the cert-manager
infrastructure. 

The admins aren't defined in any public file. The admins are the GitHub members
on the cert-manager org that are set as "Owner". Additionally, admins have their
email listed in GCP so that they can perform releases.

### Becoming an Admin

To become an admin, you must already be a maintainer for a time and have some
understanding of the technologies used in the cert-manager infrastructure (e.g.,
Prow). Then, create an issue on the cert-manager project and mention each
maintainer. Each maintainer will need to comment on the issue to express their
approval.

### Privileges

- Can remove protected branches and change settings in the GitHub organization.
- Can run the Google Cloud Build playbooks to release new versions of cert-manager.

### Responsibilities

- Must be responsible with the privileges granted to them
- Must manage cert-manager membership requests in a timely manner when requested using the process outlined in the Member Role section above.
