<p align="center"><img src="./logo/logo.png" width="250x" /></p>
<p align="center"><a href="https://prow.build-infra.jetstack.net/?job=ci-cert-manager-bazel">
<!-- prow build badge, godoc, and go report card-->
<img alt="Build Status" src="https://prow.build-infra.jetstack.net/badge.svg?jobs=ci-cert-manager-bazel">
</a>
<a href="https://godoc.org/github.com/cert-manager/cert-manager"><img src="https://godoc.org/github.com/cert-manager/cert-manager?status.svg"></a>
<a href="https://goreportcard.com/report/github.com/cert-manager/cert-manager"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/cert-manager/cert-manager" /></a></p>

# cert-manager

cert-manager is a Kubernetes add-on to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.

It is loosely based upon the work of [kube-lego](https://github.com/jetstack/kube-lego)
and has borrowed some wisdom from other similar projects e.g.
[kube-cert-manager](https://github.com/PalmStoneGames/kube-cert-manager).

![cert-manager high level overview diagram](https://cert-manager.io/images/high-level-overview.svg)

## Documentation

Documentation for cert-manager can be found at [cert-manager.io](https://cert-manager.io/docs/).
Please make sure to select the correct version of the documentation to view on
the top right of the page.

Issues and PRs towards the documentation should be filed in the [website repo](https://github.com/cert-manager/website/).

For the common use-case of automatically issuing TLS certificates to
Ingress resources, aka a [kube-lego](https://github.com/jetstack/kube-lego)
replacement, see the [cert-manager nginx ingress quick start
guide](https://cert-manager.io/docs/tutorials/acme/ingress/).

See [Installation](https://cert-manager.io/docs/installation/)
within the [documentation](https://cert-manager.io/docs)
for installation instructions.

## Troubleshooting

If you encounter any issues whilst using cert-manager, we have a number of places you
can use to try and get help.

First of all we recommend looking at the [troubleshooting guide](https://cert-manager.io/docs/faq/troubleshooting/) of our documentation.

The quickest way to ask a question is to first post on our Slack channel (#cert-manager)
on the [Kubernetes Slack](http://slack.kubernetes.io/).
There are a lot of community members in this channel, and you can often get an answer
to your question straight away!

You can also try [searching for an existing issue](https://github.com/cert-manager/cert-manager/issues).
Properly searching for an existing issue will help reduce the number of duplicates,
and help you find the answer you are looking for quicker.

Please also make sure to read through the relevant pages in the [documentation](https://cert-manager.io/docs/)
before opening an issue. You can also search the documentation using the search box on the
top left of the page.

If you believe you have encountered a bug, and cannot find an existing issue similar to your
own, you may [open a new issue](https://github.com/cert-manager/cert-manager/issues).
Please be sure to include as much information as possible about your environment.

## Community

There is a Google Group used for project wide announcements and development coordination.
Anybody can join the group by visiting [here](https://groups.google.com/forum/#!forum/cert-manager-dev)
and clicking "Join Group". A Google account is required to join the group.
Joining this group will also invite you to the cert-manager development meetings.

### Bi-weekly development meeting
Once you have become a member, you should receive an invite to the bi-weekly development
meeting, hosted on **Wednesdays at 5pm UK Time** on Google Meet.

Anyone is welcome to join these calls, even if just to ask questions.  
Meeting notes are recorded in [Google docs](https://docs.google.com/document/d/1Tc5t6ylY9dhXAan1OjOoldeaoys1Yh4Ir710ATfBa5U).

### Daily standups
You are also welcome to join our daily standup every day at **10.30am UK Time** on Google Meet.
Invites are sent via the [Google Group](https://groups.google.com/forum/#!forum/cert-manager-dev)

## Contributing

We welcome pull requests with open arms! There's a lot of work to do here, and
we're especially concerned with ensuring the longevity and reliability of the
project.

Please take a look at our [issue tracker](https://github.com/cert-manager/cert-manager/issues)
if you are unsure where to start with getting involved!

We also use the #cert-manager channel on kubernetes.slack.com for chat relating to
the project.

Developer documentation is available in the [official documentation](https://cert-manager.io/docs/contributing/).

## Changelog

The [list of releases](https://github.com/cert-manager/cert-manager/releases)
is the best place to look for information on changes between releases.

<sub><sup>Logo design by [Zoe Paterson](https://zoepatersonmedia.com)</sup></sub>
