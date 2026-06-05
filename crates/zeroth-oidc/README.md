# zeroth-oidc

OIDC protocol helpers shared by the Zeroth issuer and relying-party apps.

The crate stays dependency-light and does not perform HTTP. Product Workers can
use it to:

- calculate and validate PKCE S256 challenges
- construct `/authorize` URLs for public browser/native clients
- parse callback responses while checking `state` and Zeroth's `iss`
- encode `/oauth/token` form bodies for code and refresh-token grants
- deserialize token responses
- verify Zeroth ES256 access and ID tokens against Zeroth's JWKS, issuer,
  audience, expiry, token use, and nonce

Server-side product gates should redirect users to Zeroth, exchange the returned
code with the original `code_verifier`, validate the returned Zeroth token for
the product client, then issue a product-local session cookie. The crate does
not fetch discovery, JWKS, or token endpoints; product Workers decide how to
fetch and cache those HTTP responses.
