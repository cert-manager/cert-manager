# cert-manager Governance

This document defines project governance for the cert-manager project.  
It contains a list of roles that can be held by humans, and any additional
requirements, privileges, and responsibilities that come with each role.  
A role is held by a person, and a person can hold multiple roles.

## Contributor Role

cert-manager is for everyone. Anyone can become a cert-manager contributor
simply by contributing to the project, whether through code, documentation, blog
posts, community management, or other means. As with all cert-manager community
members, contributors are expected to follow the [cert-manager Code of
Conduct][coc].

All contributions to cert-manager code, documentation, or other components in
the cert-manager GitHub org must follow the guidelines in [the contributing
page][contrib]. Whether these contributions are merged into the project is the
prerogative of the reviewers, approvers and/or maintainers.

### Requirements
- Contribute to the project in some way.

### Privileges
- Create issues and pull requests in the cert-manager GitHub org.

### Responsibilities
- Follow the [cert-manager Code of Conduct][coc].
- Follow the [contributing guidelines][contrib].

## Member Role

Members are continuously active contributors.  
Members are expected to remain active contributors.

**Defined by:** Member of the cert-manager GitHub organization

### Requirements
- You must be a contributor.
- Enabled [two-factor authentication] on their GitHub account
- Must be part of the [cert-manager-dev] Google group
- Must be part of the [cert-manager](https://kubernetes.slack.com/messages/cert-manager) Slack channel
- Must be part of the [cert-manager-dev](https://kubernetes.slack.com/messages/cert-manager-dev) Slack channel
- Sponsored by 2 reviewers. Note the following requirements for sponsors:
    - Sponsors must have close interactions with the prospective member - e.g. code/design/proposal review, coordinating on issues, etc.
    - Sponsors must be reviewers or approvers.
- Open an issue against the cert-manager/org repo
    - Ensure your sponsors are @mentioned on the issue.
    - Include a list of your contributions to the project.
- Have your sponsors reply confirmation of sponsorship: +1
- Once your sponsors have responded, your request will be reviewed by a cert-manager admin, in accordance with their SLO. Any missing information will be requested.

[two-factor authentication]: https://help.github.com/articles/about-two-factor-authentication
[cert-manager-dev]: https://groups.google.com/forum/#!forum/cert-manager-dev

### Privileges
- Is a member of the cert-manager GitHub organization

### Responsibilities
- Remain an active contributor to the project. If you have not been able to contribute to the project in longer than 18 months, you will be removed from the organization. You must respond to any raised member inactivity issues on the cert-manager/org repo in which you are @mentioned as the inactive member within 30 days to prove your activity.
- Monitor the cert-manager-dev and cert-manager-dev channels on Slack, and help out when possible.

## Reviewer Role

Reviewers are able to review code for quality and correctness on some part of cert-manager.  
They are knowledgeable about both the codebase and software engineering principles.

**Defined by:** `reviewers` entry in the cert-manager [OWNERS][] file

### Requirements
- You must be a contributor.
- You can be trusted to review PRs thoroughly.
- Knowledgeable about the relevant part of the codebase, and can be referenced for questions about it.
- Must have made a substantial contribution to the project that indicates their knowledge of (part of) the codebase.
- Sponsored by 1 approver. Note the following requirements for sponsors:
    - Sponsors must have close interactions with the prospective reviewer - e.g. code/design/proposal review, coordinating on issues, etc.
    - Sponsors must be approvers.
- Open a PR to update the OWNERS file
    - Ensure your sponsor is @mentioned on the PR.
    - Include a list of your substantial contributions to the project.

### Privileges
- Can /lgtm on pull requests

### Responsibilities
- When possible, review pull requests, triage issues, and fix bugs in their areas
  of expertise
- Ensure that all changes go through the project's code review and integration processes.

## Approver Role

= (in CNCF terms) comitter

Code approvers are able to both review and approve code contributions. While code review is focused on code quality and correctness, approval is focused on holistic acceptance of a contribution including: backwards / forwards compatibility, adhering to API and flag conventions, subtle performance and correctness issues, interactions with other parts of the system, etc.

**Defined by:** `approvers` entry in the cert-manager [OWNERS][] file

### Requirements
- You must be a reviewer.
- Your interests mostly align with the project's direction as determined by the maintainers and steering committee.
- You have successfully reviewed & /lgtm'ed 5 PRs.
- Sponsored by 1 maintainer. Note the following requirements for sponsors:
    - Sponsors must have close interactions with the prospective reviewer - e.g. code/design/proposal review, coordinating on issues, etc.
    - Sponsors must be maintainer.
- Open a PR to update the OWNERS file
    - Ensure your sponsor is @mentioned on the PR.
    - Include a list of the 5 PRs you reviewed & /lgtm'ed.

### Privileges
- Can /approve on pull requests

### Responsibilities
- Expected to be responsive to review requests.
- Stay up to date with the project's direction and goals. eg. by attending the weekly and/or bi-weekly meetings.

## Maintainer Role

= (in CNCF terms) maintainer

Someone who can communicate with the CNCF on behalf of the project and who can
participate in a "maintainers vote".

**Defined by:** the list in the [MAINTAINERS.md][] file

### Requirements
- You must be an approver.
- You have successfully reviewed & /approved'ed 10 PRs.
- Must be able to dedicate time to participate in maintainer meetings.
- Must be able to dedicate time to participate in maintainer votes.
- Must be able to dedicate time to monitor the cert-manager-\* mailing lists and help out when possible.
- Must be able to dedicate time to rapidly respond to any time-sensitive security release processes.
- Must be able to dedicate time to attend meetings with the cert-manager Steering Committee.
- Must be able to dedicate time to communicate with the CNCF on behalf of the project.

### Privileges
- Can communicate with the CNCF on behalf of the project.
- Can participate in a "maintainers vote".

### Responsibilities
- Monitor cncf-cert-manager-\* emails and help out when possible.
- Rapidly respond to any time-sensitive security release processes.
- Attend meetings with the cert-manager Steering Committee.
- Participate in "maintainer votes".

### Maintainer Decision-Making (maintainers vote)

Substantial changes to the project, require a "maintainers vote". This includes,
but is not limited to, changes to the project's roadmap, changes to the project's
scope, fundamental design decisions, and changes to the project's governance. 

A maintainer vote is a simple majority in which each maintainer receives one vote.

### Stepping Down as a Maintainer

If a maintainer is no longer interested in or cannot perform the duties listed
above, they should move themselves to emeritus status. If necessary, this can
also occur through the decision-making process outlined above.

A review of the [MAINTAINERS.md][] file is performed every year by the current maintainers.
During this review, the maintainers that have not been active in the last 18 months
are asked whether they would like to become an emeritus maintainer, they are expected
to respond within 30 days. If they do not respond, they will automatically be moved to
emeritus status.

[coc]: https://github.com/cert-manager/cert-manager/blob/master/CODE_OF_CONDUCT.md
[contrib]: https://cert-manager.io/docs/contributing/

## Admin Role

An admin is a maintainer who has admin privileges on the cert-manager infrastructure.

**Defined by:** Admins of the cert-manager GitHub organization

### Requirements
- You must be a maintainer.
- You must have a good understanding of the technologies used in the cert-manager infrastructure.

### Privileges
- Can perform administrative tasks on the cert-manager infrastructure
- Can release new versions of cert-manager

### Responsibilities
- Must be responsible with the privileges granted to them
- Must manage cert-manager membership requests in a timely manner when requested using the process outlined in the Member Role section above.

