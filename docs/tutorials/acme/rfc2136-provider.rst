RFC-2136 Provider Support Tutorial
==================================

The goal of this document is to provide a configuration overview of the
various facilities required to deploy cert-manager against a RFC-2136
compliant DNS server such as BIND ``named``. This capability is also
commonly known as “dynamic DNS”.

Unlike the other cert-manager DNS integrations, ``named`` is a bit of a
“Swiss Army Knife” of domain name servers. Over the years, it has been
highly optimized to provide maximal vertical scalability for a single
node, as well as horizontal scalability with service provider
interfaces. While it would be nice, it’s beyond the scope of this
document to go into every possible ``named`` deployment that a user may run
in to. Instead, this document will try to make sure your server is ready
to accept requests from cert-manager using command line tools, then get
on to the making the two work together.

Transaction Signatures == TSIG
------------------------------

Dynamic DNS updates are essentially server queries which otherwise might
return resource records (RRs). Since DNS servers are commonly exposed to
the public internet, being able to push an update to a server that
responds to queries would be immediately untenable.

In the eyes of the ``named`` architects, the generic solution to this
problem space was twofold. The first is to require manual enablement of
updates at a zone level, such as ``example.com``. In a naive network,
there is no requirement that zone updates have any security to them, and
clients can be configured such that they can provide updates without any
authentication. An example of where this is useful is for machines
booting using DHCP, in this case the machines know about themselves and
the DNS server can be configured to accept updates when they come from
the address being configured.

This clearly has limitations in situations such as cert-manager and the
DNS-01 challenge. In this environment, a TXT RR must be created after
coordination with the ACME server such that the server can validate the
domain is legitimately engaged with the process of creating a
certificate for it. The resource record that must be manipulated in this
case is not the RR for a host, rather, it is a TXT RR, which is really
just a string-to-string key value pair. In the hierarchy of DNS, this
means that an arbitrary actor (cert-manager, in this case) must be able
to add one of these KV mappings to the domain and delete it after the
certificate has been issued. cert-manager does not have a convenient
physical characteristic such as a DHCP allocation.

For cases like this, we need to be able to sign a request that is being
sent to the DNS server. We do that through TSIGs, or Transaction
SIGnatures.

Configuration Step 1 - Set up your DNS server for secure dynamic updates
------------------------------------------------------------------------

There are many excellent tutorials on the net that walk through
preparing a basic ``named`` server for dynamic updates:

-  https://www.cyberciti.biz/faq/unix-linux-bind-named-configuring-tsig/
-  https://tomthorp.me/blog/using-tsig-enable-secure-zone-transfers-between-bind-9x-servers

More complex ``named`` deployments will not use text files, but rather
may use LDAP or SQL for a database for resource records. An additional
wrinkle is metadata configuration, such as for zone metadata like
enabling dynamic updates or access control lists (ACLs) for a zone.
There are too many configurations to go into here, but you should be
able to find the documentation to do so.

Whatever your deployment is, the goal at this stage has nothing to do
with cert-manager and everything to do with a tool called ``nsupdate``
generating updates signed with TSIG. Once this is out of the way, you
can attack the cert-manager configuration with far greater confidence.

Using ``nsupdate``
~~~~~~~~~~~~~~~~~~

Most paths to configuring BIND ``named`` will go through using
``dnssec-keygen``. This command-line tool generates a named private key
that is used for signing TSIG requests. When a request is signed, both
the signature and the name of the private key are attached to the
request in an unencrypted form. In this manner, when the request is
received, the name of the private key can be used to by the recipient to
find the private key itself, build a new signature with it, and compare
the two for acceptance.

Since there are dozens of ways to have your ``named`` server
misconfigured, we’ll use ``nsupdate`` to test that the server behaves as
expected before we get there.
https://debian-administration.org/article/591/Using_the_dynamic_DNS_editor_nsupdate
is a solid breakdown of how to use the tool.

To get started, we’ll simply run ``nsupdate -k <keyID>`` where keyID is
the value returned from ``dnssec-keygen``. This will read the key from
disk and provide a command prompt to issue commands. In general, we want
to write a simple TXT RR and make sure we can delete it.

::

   $ nsupdate -k <keyID>
   > update add www1.example.com txt testing
   > send
   > … test here with ``nslookup``
   > update delete www1.example.com txt
   > send
   > … test here with ``nslookup``

Any failures to write, read or delete the record will mean that
cert-manager will not be able to do so either, no matter how well it is
configured.

Configuration Step 2 - Set up cert-manager
------------------------------------------

Now we get to the fun stuff, seeing everything work. Remember that we
need to set up the ACME DNS-01 issuer and challenge mechanism as well as
the ``rfc2136`` provider. Since the documentation covers the other parts
sufficiently, let’s focus on the provider here.

.. code:: yaml
       rfc2136:
         nameserver: <address of authoritative nameserver configured above>
         tsigKeyName: <key name used in `dnssec-keygen`, use something semantically meaningful in both environments>
         tsigAlgorithm: HMACSHA512 // should be matched to the algo you chose in `dnssec-keygen`
         tsigSecretSecretRef:
           name: <the name of the k8s secret holding the TSIG key.. not the key itself!>
           namespace: <define if not `default`>
           key: <name of the key *inside* the secret>

Example:

.. code:: yaml

       rfc2136:
         nameserver: 1.2.3.4:53
         tsigKeyName: example-com-secret
         tsigAlgorithm: HMACSHA512
         tsigSecretSecretRef:
           name: tsig-secret
           namespace: cert-manager
           key: tsig-secret-key

For this example configuration, we’ll need the following two commands.
The first, on your ``named`` server generates the key. Note how
``example-com-secret`` is both in the ``tsigKeyName`` above and the
``dnssec-keygen`` command that follows.

::

   dnssec-keygen -r /dev/urandom -a HMAC-SHA512 -b 512 -n HOST example-com-secret

Also note how the ``tsigAlgorithm`` is provided in both the
configuration and the keygen command. They are listed at
https://github.com/miekg/dns/blob/v1.0.12/tsig.go#L18-L23.

The second bit of configuration you need on the kubernetes side is to
create a secret. Pulling the secret key string from the
``<key>.private`` file generated above, use the secret in the
placeholder below:

::

   kubectl -n cert-manager create secret generic tsig-secret --from-literal=tsig-secret-key=<somesecret>

Note how the ``tsig-secret`` and ``tsig-secret-key`` match the
configuration in the ``tsigSecretSecretRef`` above.

What’s next?
------------

This configuration so far will actually do nothing. You still have to
request a certificate!
