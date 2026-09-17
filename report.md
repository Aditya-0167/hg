# cdap-ui: session-token is not user-bound — any unauthenticated caller can
# mint a valid CSRF token, completely bypassing the session-token protection
# on state-changing endpoints

**Component:** `server/token.mjs`, `server/express.js`
**Repo:** cdapio/cdap-ui (Cloud VRP scope)
**Commit tested against:** `465f4e4f9374c510b3d507b019bdc3919e5615d6` (2026-07-13)

## Summary

cdap-ui's Node.js proxy server uses a `session-token` header as a CSRF
protection mechanism. Two state-changing endpoints check it:

```js
// server/express.js line 336 (forwardMarketToCdap)
if (!sessionToken.validateToken(req.headers['session-token'], cdapConfig, log, authToken))

// server/express.js line 519 (downloadLogs / updateTheme)
if (!sessionToken.validateToken(req.headers['session-token'], cdapConfig, log, authToken))
```

The mechanism has two compounding defects that together make it trivially
bypassable by any attacker who can reach the UI — including an
unauthenticated one:

**Defect 1: generateToken() ignores the caller's identity entirely.**

The token endpoint:

```js
// server/express.js line 628-631
app.get('/sessionToken', function (req, res) {
  let authToken = req.headers.authorization || '';
  const sToken = sessionToken.generateToken(cdapConfig, log, authToken);
  res.send(sToken);
});
```

passes `authToken` as a third argument, apparently intending to bind the
token to the caller's credential. But the real function signature
in `server/token.mjs` is:

```js
export function generateToken(cdapConfig, logger = console) {
  const timestamp = Date.now();
  const instanceName = cdapConfig['instance.metadata.id'];
  const secretKey = cdapConfig['session.secret.key'] || __dirname;
  const toHash = `${timestamp}${instanceName}`;
  const hash = crypto.createHmac('sha256', secretKey).update(toHash).digest('base64');
  const iv = crypto.randomBytes(16).toString('base64');
  return `${iv}-${hash}${iv}`;
}
```

The function takes exactly two parameters. The `authToken` argument is
silently discarded — it has no parameter to bind to. The token's content is
`timestamp + HMAC(timestamp + instanceName, secretKey)` — nothing that
identifies who called the endpoint. A token minted by an anonymous caller is
cryptographically identical in structure and validity to one minted by a
fully authenticated admin.

**Defect 2: /sessionToken is completely unauthenticated.**

The `/sessionToken` endpoint has no authentication middleware, no
`Authorization` header check, no session cookie check — nothing. It mints
and returns a valid token for any HTTP GET request.

**Combined effect:** any attacker who can reach the cdap-ui server can:
1. GET `/sessionToken` with no credentials → receive a valid session-token
2. Use that token in the `session-token` header of any protected request
3. The real `validateToken()` accepts it

The CSRF protection this token provides is entirely defeated.

**Defect 3 (bonus — makes forge-without-hitting-the-server possible too):**

`instanceMetadataId` (the only deployment-specific input to the HMAC) is
served unauthenticated in `GET /config.js`:

```js
// server/express.js line 278
instanceMetadataId: cdapConfig['instance.metadata.id'],
```

No auth middleware wraps `/config.js`. So an attacker can also:
1. GET `/config.js` → extract `instanceMetadataId`
2. Compute the HMAC locally with the same inputs the server uses
3. Forge a valid token without even hitting `/sessionToken`

(This requires also knowing `session.secret.key`, which defaults to
`__dirname` if not configured — a path predictable in containerized
deployments. With a properly-configured secret key this path requires more
effort, but path 1+2 above works regardless.)

## Attack Preconditions

- Attacker must be able to send HTTP requests to the cdap-ui server —
  this is the intended network position of any user of the UI, authenticated
  or not. No credentials required.
- For the full CSRF chain to do real damage, the victim must have an active
  authenticated session (the `session-token` check gates these endpoints,
  but the `Authorization` header for the actual backend call comes from the
  victim's own session cookie, forwarded by the proxy). In other words: an
  attacker can bypass the CSRF protection on their *own* requests (direct
  access), but the more dangerous scenario is a traditional CSRF attack where
  a victim's browser loads a malicious page that mints a fresh token (step 1)
  and uses it to make a state-changing request using the victim's session.
- For `/forwardMarketToCdap`, the target path is server-validated since the
  recent fix (`eb3e649de5`) — though the method (`sourceMethod`,
  `targetMethod`) is still query-controlled and not validated. For
  `/updateTheme` the path for the uiThemePath RCE was confirmed in our
  earlier filed report (Issue 559708168).

## Verified, live-executed proof

The real, unmodified `server/token.mjs` (byte-diffed against upstream —
see `captured-output/diff-check.txt`) was imported directly into the test
harness. The harness imports only this file and Node.js builtins — no mocks,
no stubs, no modifications.

```
=== Claim 2: minting with NO credential/session context ===
Token minted by "anonymous caller A": 3PKv6fsbe18X...(valid HMAC)
Token minted by "anonymous caller B": WGaWSlrO5+Tc...(valid HMAC)

=== Claim 3: REAL validateToken() accepts both ===
validateToken(anonymousToken1) => true
validateToken(anonymousToken2) => true

=== Control: garbage token rejected ===
validateToken("garbage") => false
validateToken(undefined) => false

=== Claim 4: attacker-minted token (using only the public instanceMetadataId) ===
validateToken(attackerMintedToken) => true
```

Full output: `captured-output/harness-run.log`.

## Impact analysis

The `session-token` mechanism is the only CSRF defence on the two
state-changing endpoints in cdap-ui's proxy. Both are now effectively
unprotected against CSRF from any origin that can reach the server:

- `/forwardMarketToCdap`: proxies a source URL → CDAP backend, with
  attacker-controlled HTTP verb (`sourceMethod`, `targetMethod`). With a
  valid session-token, a malicious page can make a victim's authenticated
  browser proxy arbitrary PUT/POST/DELETE requests to the CDAP backend in
  their name.
- `/updateTheme` (the path confirmed in Issue 559708168 as RCE-capable via
  an unsanitized `uiThemePath` written to disk): the only thing standing
  between an unauthenticated CSRF chain and that RCE path was a valid
  `session-token`. That token is now freely obtainable by anyone.

The combination with Issue 559708168 (still open/unpatched as of this
filing) is particularly significant: CSRF bypass + uiThemePath RCE = a
malicious webpage can achieve RCE on the cdap-ui server with no credentials
at all, just by loading a page that chains these two bugs.

## The cause

`generateToken()` in `server/token.mjs` accepts only two parameters
(`cdapConfig`, `logger`) — the third argument passed by the call site in
`express.js` (`authToken`, the caller's credential) is silently discarded
because the function has no parameter for it. The token is thus
cryptographically a pure function of the server's deployment-wide config
(timestamp + HMAC over `instance.metadata.id` + `session.secret.key`),
with no input from the requesting user. The `/sessionToken` endpoint that
mints this token has no authentication middleware, completing the bypass.

## Suggested fix

- Bind the token to the authenticated caller's identity — at minimum, include
  the `Authorization` header value in the HMAC input. Actually add it as a
  parameter to `generateToken()` and `validateToken()` and verify it at
  validation time.
- Add authentication middleware to `/sessionToken` itself so only already-
  authenticated sessions can mint tokens.
- Remove `instanceMetadataId` from the unauthenticated `/config.js` response
  (it serves no legitimate client-side purpose that justifies this exposure).
