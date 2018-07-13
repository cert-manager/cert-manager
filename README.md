# cert-manager


cert-manager is a Kubernetes add-on to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.

It is loosely based upon the work of [kube-lego](https://github.com/jetstack/kube-lego)
and has borrowed some wisdom from other similar projects e.g.
[kube-cert-manager](https://github.com/PalmStoneGames/kube-cert-manager).

![cert-manager high level overview diagram](/docs/images/high-level-overview.png)

## Current status

This project is not yet ready to be a component in a critical production stack,
however it *is* at a point where it offers comparable features to other
projects in the space. If you have a non-critical piece of infrastructure, or
are feeling brave, please do try cert-manager and report your experience here
in the issue section.

**NOTE:** currently we provide no guarantees on our API stability. This means
there may be breaking changes that will require changes to *all*
`Issuer`/`Certificate` resources you have already created. We aim to provide a
stable API after a 1.0 release.

## Documentation

Documentation for cert-manager can be found at [cert-manager.readthedocs.io](https://cert-manager.readthedocs.io/en/latest/).
Please make sure to select the correct version of the documentation to view on
the bottom left of the page.

## Troubleshooting

If you encounter any issues whilst using cert-manager, and your issue is not
documented, please [file an issue](https://github.com/jetstack/cert-manager/issues).

## Community

There is a Google Group used for project wide announcements and development coordination.
Anybody can join the group by visiting [here](https://groups.google.com/forum/#!forum/cert-manager-dev)
and clicking "Join Group". A Google account is required to join the group.

Once you have become a member, you should receive an invite to the weekly development
meeting, hosted on **Wednesdays at 4pm UTC** on Zoom.us.

Anyone is welcome to join these calls, even if just to ask questions.

Meeting notes are recorded in [Google docs](https://docs.google.com/document/d/1Tc5t6ylY9dhXAan1OjOoldeaoys1Yh4Ir710ATfBa5U).

## Contributing

We welcome pull requests with open arms! There's a lot of work to do here, and
we're especially concerned with ensuring the longevity and reliability of the
project.

Please take a look at our [issue tracker](https://github.com/jetstack/cert-manager/issues)
if you are unsure where to start with getting involved!

We also use the #cert-manager channel on kubernetes.slack.com for chat relating to
the project.

Developer documentation is available in the [official documentation](http://cert-manager.readthedocs.io/en/latest/devel/index.html).

## Changelog

The [list of releases](https://github.com/jetstack/cert-manager/releases)
is the best place to look for information on changes between releases.
