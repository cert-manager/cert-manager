==========
Challenges
==========

Challenge resources are used by the ACME issuer to manage the lifecycle of an
ACME 'challenge' that must be completed in order to complete an 'authorization'
for a single DNS name/identifier.

When an **Order** resource is created, the order controller will create
Challenge resources for each DNS name that is being authorized with the ACME
server.

As an end-user, you will never need to manually create a Challenge resource.
Once created, a Challenge cannot be changed. Instead, a new Challenge resource
must be created.

Challenge lifecycle
===================

After a Challenge resource has been created, it will be initially queued for
processing.
Processing will not begin until the challenge has been 'scheduled' to start.
This scheduling process prevents too many challenges being attempted at once,
or multiple challenges for the same DNS name being attempted at once.
For more information on how challenges are scheduled, read the
`challenge scheduling`_ section.

Once a challenge has been scheduled, it will first be 'synced' with the ACME
server in order to determine its current state. If the challenge is already
valid, its 'state' will be updated to 'valid', and also set
``status.processing = false`` to 'unschedule' itself.

If the challenge is still 'pending', the challenge controller will 'present'
the challenge using the configured solver, one of HTTP01 or DNS01.
Once the challenge has been 'presented', it will set ``status.presented=true``.

Once 'presented', the challenge controller will perform a 'self check' to
ensure that the challenge has 'propagated' (i.e. the authoritve DNS servers
have been updated to respond correctly, or the changes to the ingress resources
have been observed and in-use by the ingress controller).

If the self check fails, cert-manager will retry the self check with a fixed
10 second retry interval. Challenges that do not ever complete the self check
will continue retrying until the user intervenes.

Once the self check is passing, the ACME 'authorization' associated with this
challenge will be 'accepted' (TODO: add link to accepting challenges section of
ACME spec).

The final state of the authorization after accepting it will be copied across
to the Challenge's ``status.state`` field, as well as the 'error reason' if
an error occurred whilst the ACME server attempted to validate the challenge.

Once a Challenge has entered the ``valid``, ``invalid``, ``expired`` or
``revoked`` state, it will set ``status.processing=false`` to prevent any
further processing of the ACME challenge, and to allow another challenge to be
scheduled if there is a backlog of challenges to complete.

Challenge scheduling
====================

Instead of attempting to process all challenges at once, challenges are
'scheduled' by cert-manager.

This scheduler applies a cap on the maximum number of simultaneous challenges
as well as disallows two challenges for the same DNS name and solver type
(http-01 or dns-01) to be completed at once.

The maximum number of challenges that can be processed at a time is 60 as of
ddff78_.

Debugging Challenge resources
=============================

In order to determine why an ACME Certificate is not being issued, we can debug
using the 'Challenge' resources that cert-manager has created.

In order to determine which Challenge is failing, you can run
``kubectl get challenges``:

.. code-block:: shell

    $ kubectl get challenges

    NAME                      STATE     DOMAIN            REASON                                     AGE
    example-com-1217431265-0  pending   example.com       Waiting for dns-01 challenge propagation   22s

This shows that the challenge has been presented using the DNS01 solver
successfully and now cert-manager is waiting for the 'self check' to pass.

You can get more information about the challenge by using ``kubectl describe``:

.. code-block:: shell

    $ kubectl describe challenge example-com-1217431265-0

    ...
    Status:
      Presented:   true
      Processing:  true
      Reason:      Waiting for dns-01 challenge propagation
      State:       pending
    Events:
      Type    Reason     Age   From          Message
      ----    ------     ----  ----          -------
      Normal  Started    19s   cert-manager  Challenge scheduled for processing
      Normal  Presented  16s   cert-manager  Presented challenge using dns-01 challenge mechanism

Progress about the state of each challenge will be recorded either as Events
or on the Challenge's ``status`` block (as shown above).

Troubleshooting failing challenges
==================================

.. todo::
   add section describing common issues and resolutions when challenges are
   failing

.. _ddff78: https://github.com/jetstack/cert-manager/blob/ddff78f011558e64186d61f7c693edced1496afa/pkg/controller/acmechallenges/scheduler/scheduler.go#L31-L33
