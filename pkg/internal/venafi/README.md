## Why are we trying to avoid storing username-password or client-cert in a Kubernetes Secret?

If a username-password or a client-cert is leaked it allows an attacker to do everything that that user is permitted;
potentially far more than tightly scoped access to certain API endpoints.
For example, it could allow to the holder to access the TPP web admin pages,
and from there change perform all the operations granted to that user in the webUI,
to change their password, to create and delete teams, join, and remove members from teams,
to create their own access-tokens and refresh-tokens with applications and scope of their choice.
including some or all of manage SSH keys, Certificates, SSH keys, Configuration etc.

If when the leak was noticed, the only way to revoke access would be to change the password or disable the account in TPP.
And if other cert-managers or other integrated applications are also using this account, you would need to go and reconfigure those too.
Else if you have chosen to create separate accounts for those other applications, you have also multiplied the number of accounts in TPP which you have to manage and monitor.

## Why are we trying to avoid using the legacy username-password / api-key mechanism?

In short, because it's deprecated and causes problems in clustered TPP installations.

If you supply a TPP username-password to the vcert.NewClient function,
it causes vcert to use an "api-key" to authenticate to the TPP resource API server.
This "api-key" mechanism is deprecated and scheduled to be removed in the next couple of TPP releases.

The reason (as I understand it) is that this legacy system required each TPP server to maintain some local state;
namely the api-keys issued to each user that authenticated with that server.
This means that TPP administrators need to manage session affinity for API clients when the scale-out a TPP cluster.

## Why not update cert-manager to use the username-password or client-cert to get an access-token?

Because while it overcomes the session-affinity problem,
it does not address the security concerns described earlier.

We'd need to change the Venafi Issuer code to use lower level vcert APIs...to create a tpp.Endpoint directly,
which allows us to then supply the username-password with the TPP specific GetRefreshToken method,
which returns an Oauth2 access-token (and a refresh-token, depending on how TPP is configured)
We could perform this two-step process each time the Venafi Issuer or CertificateRequest controller instantiates a vcert client,
each time Sync is called.

We will have to implement this if we want to continue to support the username-password configuration method, with newer versions of TPP.

## And furthermore...

It introduces another potential scalability problem; the overloading of the oauth2 authorization service in busy / clustered TPP installations.
*I believe* that there are customers with busy clustered TPP servers where the oauth2 authorization server has become a bottleneck.

In its oauth2 system, [TPP uses self-encoded access-tokens](https://www.oauth.com/oauth2-servers/access-tokens/self-encoded-access-tokens/).
This allows the resource API server to authenticate and do access-control for requests that have a correctly signed self-encoded access-token,
without having to trouble the authentication server.
This allows the TPP resource API server to be scaled-out without overloading the authentication server.

But if cert-manager is performing an authorization step before every Venafi Issuer operation,
it may overload the authorization server,
especially if there are many Venafi issued certificates to be reconciled.
And it will cause a build up of many unused "refresh-tokens" on the authorization server;
these have to be stored and managed.

So for this reason  we would aim to store and re-use the access-token, for its lifetime.
We could store the access-tokens for each Issuer in-memory, but we'd have to be sure to use the *correct* access-token for each Issuer or CertificateRequest controller Sync.
If we get this wrong, it might give a Certificate creator access to certificates in another users TPP policy folder (I think)....but at best it would cause lots of confusion.
We'd need to add lock / synchronize access to this in-memory map, so that both the Issuer controller and the CertificateRequest controllers to be able to update it if the access-token expires.
We could alternatively maintain multiple long lived vcert client instances and associate those *correctly* with their respective Issuer, with the same locking problem as above.
But neither of these would help if cert-manager is restarted, in which case it re-authenticates causing another unnecessary request to the authorization server
and another unused refresh-token to be stored there.

An alternative is to store the access-token (and the refresh-token, see below) to a Kubernetes Secret.
In this implementation so far I'm storing it to the same Secret that was supplied by the administrator who created the Issuer.
But I agree that it would be better to store it to a separate Secret to avoid it being clobbered by GitOps systems.

With the access-token saved to a Secret, the access-token can be used even after a cert-manager restart
and the Secret provides a point of co-ordination for the Issuer controller and the CertificateRequest controller which may both need to refresh the access-token
(either by the username-password route or by the refresh-token route, below)

## OK, so a long-lived access-token in a Kubernetes Secret sounds ideal

An improvement is to have a single user account and for the owner of that account to use `vcert getcred`, to get an access-token associated with a cert-manager application in TPP.
The access-token, by virtue of that application association, is scoped to only have access to the `certificate: manage,revoke` APIs.
Store this access-token in a Kubernetes Secret and cert-manager can interact with only those APIs.
And if the access-token is leaked, the holder will only have access to those APIs.
Other applications can share that account by creating unique access-tokens for them.
This reduces the burden of managing and monitoring many service accounts for each application.

[TPP uses self-encoded access-tokens](https://www.oauth.com/oauth2-servers/access-tokens/self-encoded-access-tokens/),
which allows the TPP resource API server to be scaled-out without overloading the authentication server.
It also avoids some problems with the old username-password -> api-key mechanism, which required some state on each TPP server and which required managing session affinity for API clients.

The problem is that if there the client only has an access-token, then the access-token has to be

It also allows the...

TBC
