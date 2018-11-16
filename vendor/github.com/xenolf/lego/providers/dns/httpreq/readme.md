# HTTP request

The server must provide:
- `POST` `/present`
- `POST` `/cleanup`

The URL of the server must be define by `HTTPREQ_ENDPOINT`.

## Mode

There are 2 modes (`HTTPREQ_MODE`):
- default mode:
```json
{
  "fqdn": "_acme-challenge.domain.",
  "value": "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM"
}
```

- `RAW`
```json
{
  "domain": "domain",
  "token": "token",
  "keyAuth": "key"
}
```

## Authentication

Basic authentication (optional) can be set with some environment variables:
- `HTTPREQ_USERNAME` and `HTTPREQ_PASSWORD`
- both values must be set, otherwise basic authentication is not defined.
