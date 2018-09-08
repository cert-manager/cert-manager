# Contributing to `dep`

`dep` is an open source project.

It is the work of hundreds of contributors. We appreciate your help!

Keep an eye on the [Roadmap](https://github.com/golang/dep/wiki/Roadmap) for a summary of where the project is, and where we're headed.

## Filing issues

Please check the existing issues and [FAQ](docs/FAQ.md) to see if your feedback has already been reported.

General questions should go to the [golang-nuts mailing list](https://groups.google.com/group/golang-nuts) or the [Gophers Slack #vendor channel](https://gophers.slack.com/messages/C0M5YP9LN/) instead of the issue tracker.
The gophers there will answer or ask you to file an issue if you've tripped over a bug.
For an invite to the Slack channel, [fill out this form](https://invite.slack.golangbridge.org/).

When [filing an issue](https://github.com/golang/dep/issues/new), make sure to answer these five questions:

1. What version of Go (`go version`) and `dep` (`git describe --tags`) are you using??
3. What `dep` command did you run?
4. What did you expect to see?
5. What did you see instead?

## Contributing code

Let us know if you are interested in working on an issue by leaving a comment
on the issue in GitHub. This helps avoid multiple people unknowingly 
working on the same issue.

Please read the [Contribution Guidelines](https://golang.org/doc/contribute.html)
before sending patches.

The
[help wanted](https://github.com/golang/dep/issues?q=is%3Aissue+is%3Aopen+label%3A%22help%20wanted%22)
label highlights issues that are well-suited for folks to jump in on. The
[good first issue](https://github.com/golang/dep/issues?q=is%3Aissue+is%3Aopen+label%3A%22good%20first%20issue%22)
label further identifies issues that are particularly well-sized for newcomers.

Unless otherwise noted, the `dep` source files are distributed under
the BSD-style license found in the LICENSE file.

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult [GitHub Help] for more
information on using pull requests.

We check `dep`'s own `vendor` directory into git. For any PR to `dep` where you're
updating `Gopkg.toml`, make sure to run `dep ensure` and commit all changes to `vendor`.

[GitHub Help]: https://help.github.com/articles/about-pull-requests/

## Contributing to the Documentation

All the docs reside in the [`docs/`](docs/) directory. For any relatively small
change - like fixing a typo or rewording something - the easiest way to
contribute is directly on Github, using their web code editor.

For relatively big change - changes in the design, links or adding a new page -
the docs site can be run locally. We use [docusaurus](http://docusaurus.io/) to
generate the docs site. [`website/`](website/) directory contains all the
docusaurus configurations. To run the site locally, `cd` into `website/`
directory and run `npm i --only=dev` to install all the dev dependencies. Then
run `npm start` to start serving the site. By default, the site would be served
at http://localhost:3000.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution,
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Maintainer's Guide

`dep` has subsystem maintainers; this guide is intended for them in performing their work as a maintainer.

### General guidelines

* _Be kind, respectful, and inclusive_. Really live that [CoC](https://github.com/golang/dep/blob/master/CODE_OF_CONDUCT.md). We've developed a reputation as one of the most welcoming and supportive project environments in the Go community, and we want to keep that up!
* The lines of responsibility between maintainership areas can be fuzzy. Get to know your fellow maintainers - it's important to work _with_ them when an issue falls in this grey area.
* Remember, the long-term goal of `dep` is to disappear into the `go` toolchain. That's going to be a challenging process, no matter what. Minimizing that eventual difficulty should be a guiding light for all your decisions today.
  * Try to match the toolchain's assumptions as closely as possible ([example](https://github.com/golang/dep/issues/564#issuecomment-300994599)), and avoid introducing new rules the toolchain would later have to incorporate.
  * Every new flag or option in the metadata files is more exposed surface area that demands conversion later. Only add these with a clear design plan.
  * `dep` is experimental, but increasingly only on a larger scale. Experiments need clear hypotheses and parameters for testing - nothing off-the-cuff.
* Being a maintainer doesn't mean you're always right. Admitting when you've made a mistake keeps the code flowing, the environment health, and the respect level up.
* It's fine if you need to step back from maintainership responsibilities - just, please, don't fade away! Let other maintainers know what's going on.

### Issue management

* We use [Zenhub](https://www.zenhub.com) to manage the queue, in addition to what we do with labels.
  * You will need to install [ZenHub extension](https://www.zenhub.com/extension) to your browser to show the board.
  * Pipelines, and [the board](https://github.com/golang/dep#boards) are one thing we try to utilize:
    * **New Issues Pipeline**: When someone creates a new issue, it goes here first. Keep an eye out for issues that fall into your area. Add labels to them, and if it's something we should do, put it in the `Backlog` pipeline. If you aren't sure, throw it in the `Icebox`. It helps to sort this pipeline by date.
    * **Icebox Pipeline**: Issues that we aren't immediately closing but aren't really ready to be prioritized and started on. It's not a wontfix bucket, but a "not sure if we should/can fix right now" bucket.
    * **Backlog Pipeline**: Issues that we know we want to tackle. You can drag/drop up and down to prioritize issues.
  * Marking dependencies/blockers is also quite useful where appropriate; please do that.
  * We use epics and milestones in roughly the same way (because OSS projects don't have real sprints). Epics should be duplicated as milestones; if there's a main epic issue, it should contain a checklist of the relevant issues to complete it.
* The `area:` labels correspond to maintainership areas. Apply yours to any issues or PRs that fall under your purview. It's to be expected that multiple `area:` labels may be applied to a single issue.
* The [`help wanted`](https://github.com/golang/dep/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) and [`good first issue`](https://github.com/golang/dep/labels/good%20first%20issue) labels are two of our most important tools for making the project accessible to newcomers - a key goal for our community. Here's how to use them well.
  * `good-first-pr` should be applied when there's a very straightforward, self-contained task that is very unlikely to have any hidden complexity. The real purpose of these is to provide a "chink in the armor", providing newcomers a lens through which to start understanding the project.
  * `help-wanted` should be applied to issues where there's a clear, stated goal, there is at most one significant question that needs answering, and it looks like the implementation won't be inordinately difficult, or disruptive to other parts of the system.
    * `help-wanted` should also be applied to all `good-first-pr` issues - it's duplicative, but not doing so seems unfriendly.


### Pull Requests

* Try to make, and encourage, smaller pull requests.
* [No is temporary. Yes is forever.](https://blog.jessfraz.com/post/the-art-of-closing/)
* Long-running feature branches should generally be avoided. Discuss it with other maintainers first.
* Unless it's trivial, don't merge your own PRs - ask another maintainer.
* Commit messages should follow [Tim Pope's rules](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).
* Checklist for merging PRs:
  * Does the PR pass [the code review comments](https://github.com/golang/go/wiki/CodeReviewComments)? (internalize these rules!)
  * Are there tests to cover new or changed behavior? Prefer reliable tests > no tests > flaky tests.
  * Does the first post in the PR contain "Fixes #..." text for any issues it resolves?
  * Are any necessary follow-up issues _already_ posted, prior to merging?
  * Does this change entail the updating of any docs?
     * For docs kept in the repo, e.g. FAQ.md, docs changes _must_ be submitted as part of the same PR.
