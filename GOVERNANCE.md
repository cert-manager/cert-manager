# cert-manager Governance

This document defines project governance for the cert-manager project. Its
purpose is to describe how decisions are made on the project and how anyone can
influence these decisions.

This governance charter applies to every project under the cert-manager GitHub
organisation. The term "cert-manager project" refers to any work done under the
cert-manager GitHub organisation and includes the cert-manager/cert-manager
repository itself as well as cert-manager/trust-manager,
cert-manager/approver-policy and all the other repositories under the
cert-manager GitHub organisation.

We have six levels of responsibility, each one building on the previous:

- [Contributor](#contributor),
- [GitHub Member](#github-member),
- [Reviewer](#reviewer),
- [Approver](#approver),
- [Maintainer](#maintainer),
- [Admin](#admin).

## Contributor

cert-manager is for everyone. Whether you're an experienced developer, a
dedicated documenter, a passionate community builder, or simply someone eager to
make a positive impact, cert-manager welcomes you as a valued contributor.

### Becoming a Contributor

Anyone can become a cert-manager contributor simply by contributing to the
project, whether through code, documentation, blog posts, community management,
or other means.

### Contributor Responsibilities

- Follow the [cert-manager Code of Conduct](https://github.com/cert-manager/cert-manager/blob/master/CODE_OF_CONDUCT.md).
- Follow the guidelines in [the Contributing page](https://cert-manager.io/docs/contributing/).

## GitHub Member

GitHub Members are active contributors to the cert-manager project, or one of
the related projects in the cert-manager GitHub organisation.

A contributor is considered to be active when they have had at least one
interaction (comment on an issue or PR or message in the `#cert-manager` or
`#cert-manager-dev` channels in the Kubernetes Slack) within the last 18 months.

Members that have been inactive over the past 18 months may be removed from the
GitHub organization.

**Defined by:** Member of the cert-manager GitHub organization.

### Becoming a GitHub Member

To be added as a GitHub member of the cert-manager organization, you will need
to look for two sponsors with at least the `reviewer` role. These two sponsors
must have had some meaningful interaction with you on an issue on GitHub or on
the `#cert-manager` or `#cert-manager-dev` channels on the Kubernetes Slack.

Then, open an issue on the [community][] repository and mention your sponsors as
well as links to the meaningful interactions (Slack threads, GitHub issues). Ask
your sponsors to confirm their sponsorship by commenting on your PR. After that,
your request will be reviewed by a cert-manager admin, in accordance with their
SLO.

To be added as a GitHub member, you will also need to enable [two-factor
authentication](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication) on your GitHub account.

GitHub members are encouraged to engage with the mailing list [cert-manager-dev@googlegroups.com](https://groups.google.com/g/cert-manager-dev) as well as the [`#cert-manager`](https://kubernetes.slack.com/messages/cert-manager) and [`#cert-manager-dev`](https://kubernetes.slack.com/messages/cert-manager-dev) channels on the Kubernetes Slack.

### GitHub Member Responsibilities

No extra responsabilities.

## Reviewer

The mission of the reviewer is to read through PRs for quality and correctness
on all or some part of cert-manager. Reviewers are knowledgeable about the
codebase as well as software engineering principles. Individuals with expertise
in documentation, website content, and other facets of the project are also
encouraged to join as reviewers.

**Defined by:** the `reviewers` section in the file [`OWNERS`](./OWNERS).

### Becoming a Reviewer

To become a reviewer, you will need to look for a sponsor with at least the
approver role. Your sponsor must have had close interactions with you: they must
have closely reviewed one of your PRs or worked with you on a complex issue.

Then, create a PR to add your name to the list of `reviewers` in the `OWNERS`
file on the repository in which you want to become a Reviewer. The PR
description should list your significant contributions and should mention your
sponsor. Your sponsor is expected to give their approval as a comment on your
PR. If you would like to become a reviewer for multiple repositories, you will
need to repeat the process for each repository.

### Reviewer Responsibilities

- When possible, review pull requests, triage issues, and fix bugs in their
  areas of expertise.
- Ensure that all changes go through the project's code review and integration
  processes.

### Reviewer Privileges

- Able to `/lgtm` on pull requests.

## Approver

> **Note:** some projects call this role "committer".

As an approver, your role is to make sure the right people reviewed the PRs. The
approver's focus isn't to review the code; instead, they put a stamp of approval
on an existing review with the command `/approve`. Note that it is always
possible to review a PR as an approver with `/lgtm`, in which case the PR will
be automatically approved.

**Defined by:** the `approver` section in the [`OWNERS`](./OWNERS) file.

### Becoming an Approver

To become an approver and start merging PRs, you must have reviewed 5 PRs.

You will then need to get sponsorship from one of the maintainers. The
maintainer sponsoring you must have had close work interactions with you and be
knowledgeable of some of your work.

To apply, open a PR to update the `OWNERS` file on the repository you would like
to become an Approver for and mention your sponsor in the description. The PR
description should also list the PRs you have reviewed. If you would like to
become an approver for multiple repositories, you will need to repeat the
process for each repository.

### Approver Responsibilities

- Expected to be responsive to review requests.
- Stay up to date with the project's direction and goals, e.g., by attending
  some of the bi-weekly meetings, standups, or being around in the
  `#cert-manager` and the `#cert-manager-dev` channels on the Kubernetes Slack.

### Approver Privileges

- Can `/approve` on pull requests.

## Maintainer

A maintainer is someone who can communicate with the CNCF on behalf of the
project and who can participate in lazy consensus and votes.

**Defined by:** [`MAINTAINERS.md`](./MAINTAINERS.md).

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

### Maintainer Privileges

- Can communicate with the CNCF on behalf of the project.
- Can participate in lazy consensus and votes.

### Maintainer Responsibilities

- Monitor cncf-cert-manager-\* emails and help out when possible.
- Respond to time-sensitive security release processes.
- Create and attend meetings with the cert-manager Steering Committee (not less than once a quarter).
- Attend "maintainers vote" meetings when one is scheduled.

### Maintainer Decision-Making

Substantial changes to the project require a "maintainers decision". This includes,
but is not limited to, changes to the project's roadmap, changes to the project's
scope, fundamental design decisions, and changes to the project's governance.

A "maintainers decision" is made using lazy consensus. Email or Slack
can be used to reach lazy consensus as long as the deliberation date
and time are specified and the maintainers are CC'ed. You may use the
following message template:

> Dear maintainers, I'd like us to reach an agreement on the following matter using lazy consensus: [...]
>
> - 🧑‍💻 Participants: @cert-manager-maintainers
> - 📢 Deadline: April 3rd, 2023 23:59 UTC
> - 🚨 Note: to speed up the process, you may answer with a :+1: or a comment stating that you are lazy to help reach consensus before the deadline.

Any disagreements with regards to the decision must be posted as a comment on
the Slack message or to the email thread along with an explanation of why.
Disagreements posted without justification will not be considered.

While most decisions are typically reached through the principle of lazy
consensus, there exists the option for a maintainer to propose a formal vote.
Unless otherwise specified, such a vote would require a simple majority approval
from all maintainers to be considered successful. Situations that might warrant
a formal vote include, but are not limited to, cases where a decision
necessitates explicit input from every participant or when disagreements arise
during a lazy consensus discussion.

### Stepping Down as a Maintainer

If a maintainer is no longer interested in or cannot perform the duties listed
above, they should move themselves to emeritus status. If necessary, this can
also occur through the decision-making process outlined above.

A review of the [`MAINTAINERS.md`](./MAINTAINERS.md) file is performed every
year by the current maintainers. During this review, the maintainers that have
not been active in the last 18 months are asked whether they would like to
become an emeritus maintainer, they are expected to respond within 30 days. If
they do not respond, they will automatically be moved to emeritus status.

## Admin

An admin is a maintainer who has admin privileges on the cert-manager
infrastructure.

The admins aren't defined in any public file. The admins are the GitHub members
on the cert-manager org that are set as "Owner". Additionally, admins have their
email listed in GCP so that they can perform releases.

### Becoming an Admin

To become an admin, you must already be a maintainer for a time and have some
understanding of the technologies used in the cert-manager infrastructure (e.g.,
Prow). Then, create an issue on the [community][] repository and mention each
maintainer. Each maintainer will need to comment on the issue to express their
approval.

[community]: https://github.com/cert-manager/community

### Admin Privileges

- Can change settings in the GitHub organization (e.g., remove protected
  branches, add GitHub members, etc.)
- Can run the Google Cloud Build playbooks to release new versions of
  cert-manager.

### Admin Responsibilities

- Must have availability to allocate time to perform cert-manager releases.
- Must be available to perform admin-related tasks (add a GitHub member, promote
  a GitHub user to "Owner", add someone to the GCP projects, etc.)
- Must be responsible with the privileges granted to them.
