# Zeroth AWS API Gateway authorizer

`crates/zeroth-aws-authorizer` is a reusable Rust HTTP API Lambda REQUEST authorizer for Zeroth's
short-lived issuer tokens. It validates ES256 signatures against Zeroth's HTTPS
JWKS and checks the exact issuer, audience, client ID, issue time and expiry.
Only public keys are fetched into AWS; the signing key stays with Zeroth. The
authorization result includes the signed `sub` as `context.user` for the
protected Lambda. Gateway authorizer caching should be disabled so expiry is
checked for every request. Tokens remain usable until expiry even if the Zeroth
session ends; use a short issuer token TTL (MSTR uses 300 seconds).

Deploy the Rust Lambda with:

```sh
ZEROTH_AWS_ISSUER=https://bitneedle.com/id \
ZEROTH_AWS_AUDIENCE=MSTR \
ZEROTH_AWS_CLIENT_ID=bitneedle-web \
ZEROTH_AWS_NAME=zeroth-authorizer-mstr-test \
ZEROTH_AWS_STACK=zeroth-authorizer-mstr-test \
bash deploy/aws/deploy.sh
```

The script builds a Linux ARM64 Rust bootstrap, keeps the zip in a private S3
artifact bucket, and deploys the Lambda with `ZEROTH_JWKS_URL`,
`ZEROTH_ISSUER`, `ZEROTH_AUDIENCE`, and `ZEROTH_CLIENT_ID`. Attach its output
ARN as an HTTP API REQUEST authorizer with payload version 2.0, simple
responses, identity source `$request.header.Authorization`, and zero result
cache TTL. Its role needs basic Lambda logging only.

Run `cargo test -p zeroth-aws-authorizer`.
The mastering API uses the audience `MSTR`; DNS remains lowercase at
`mstr.bitneedle.com`.
