# Browser and computer-use isolation

Browser agents combine untrusted observations with an authenticated actuator.
A page can hide instructions in rendered text, pixels, metadata, accessibility
labels, overlays, downloads, or cross-origin frames. URL allowlisting alone
does not control cookies, credential use, uploads, local files, clipboard data,
redirects, purchases, messages, or permission changes.

Trustrail therefore keeps observation and authorization separate:

1. a trusted application issues an integrity-sealed browser-session manifest;
2. instrumentation captures page state, which remains explicitly untrusted;
3. the guard binds a proposed action to the exact live session and observation;
4. sensitive actions receive a canonical preview in trusted UI and fresh,
   external approval; and
5. a trusted actuator consumes the short-lived, single-use authorization.

`BrowserIsolationGuard` is a policy and authorization boundary. It does not
launch a browser, interpret pixels, manage cookies, scan malware, provide a
sandbox, or perform an action.

## Seal a browser-session manifest

Build session configuration only from authenticated server-side state. The
manifest binds the tenant, actor, identity, ephemeral browser profile, current
and allowed origins, authenticated origins, permitted actions, cross-origin
flows, upload and local-file grants, download policy, clipboard switches,
sandbox controls, authentication-state digest, nonce, policy version, and
expiry.

```python
from datetime import UTC, datetime, timedelta

from trustrail import (
    BrowserActionType,
    BrowserIsolationPolicy,
    BrowserOrigin,
    BrowserSessionConfig,
    BrowserSessionSigner,
    browser_digest,
)

now = datetime.now(UTC)
app = BrowserOrigin(scheme="https", host="app.example")
policy = BrowserIsolationPolicy(policy_version="browser-policy-v1")
config = BrowserSessionConfig(
    session_id="session-1",
    tenant_id=authenticated_tenant_id,
    actor_id=authenticated_actor_id,
    identity_id=authenticated_identity_id,
    profile_id="ephemeral-profile-1",
    policy_version=policy.policy_version,
    current_origin=app,
    allowed_origins=(app,),
    authenticated_origins=(app,),
    allowed_actions=frozenset(
        {BrowserActionType.NAVIGATE, BrowserActionType.PURCHASE}
    ),
    sandbox_controls=policy.required_controls,
    authentication_state_digest=browser_digest(authenticated_state),
    nonce=cryptographically_random_nonce,
    expires_at=now + timedelta(minutes=10),
)
signer = BrowserSessionSigner("browser-key-v1", manifest_hmac_key)
manifest = signer.issue(config, now=now)
```

HMAC keys must contain at least 32 bytes. Keep them outside prompts, browser
profiles, page JavaScript, and model-visible context. Rotate key IDs and accept
only explicitly trusted current keys. Reissue a manifest after navigation,
authentication, profile, permission, origin, or policy state changes; do not
mutate a signed object.

Required controls default to process isolation, an ephemeral profile,
deny-by-default network egress, credential/download/upload/clipboard/local-file
brokers, cleanup on exit, and download quarantine. A manifest assertion is not
an attestation: the browser broker must actually enforce every asserted
control.

## Treat observations as untrusted data

Create a `BrowserObservation` for rendered text, pixels, accessibility trees,
page metadata, or download metadata. Trusted instrumentation supplies the URL,
origin, frame origin, element visibility, viewport fraction, enabled state,
occlusion, and sensitive-action classification. Page-controlled strings remain
data and cannot grant authority. Configure a production
`BrowserObservationVerifier` to authenticate the exact instrumentation record;
missing, failing, or throwing verification is denied. The static verifier is
only for tests and offline examples.

```python
verified = guard.require_observation(manifest, observation, now=now)
assert verified.untrusted is True
```

The guard rejects a stale or future observation, a URL/origin mismatch, an
unapproved or private origin, an origin change that has not received a new
manifest, oversized content, and elements from unapproved origins. Verification
does not make the page trustworthy; it only binds the exact untrusted snapshot
to the session.

Before an element action, the guard verifies that the referenced element exists
in that exact snapshot and is visible, in the viewport, enabled, unobscured,
origin-correct, and correctly classified. A control classified as `purchase`
cannot be downgraded to an ordinary `click`.

## Preview and authorize an action

Construct `BrowserActionRequest` from trusted orchestration state. Element
actions must reference the exact `VerifiedBrowserObservation`. URLs are parsed
as absolute HTTP(S) URLs without userinfo and matched to the declared canonical
origin. `file:`, `javascript:`, `data:`, loopback, link-local, private, reserved,
and unspecified targets fail closed by default.

```python
from trustrail import BrowserActionReviewField

request = BrowserActionRequest(
    request_id="purchase-1",
    session_id=config.session_id,
    tenant_id=config.tenant_id,
    actor_id=config.actor_id,
    action=BrowserActionType.PURCHASE,
    target_url="https://app.example/checkout",
    target_origin=app,
    element_ref="buy-button",
    observation=verified,
    review_fields=(
        BrowserActionReviewField(
            field_id="total",
            label="Total",
            value="EUR 19.95",
            highlight=True,
        ),
        BrowserActionReviewField(
            field_id="merchant",
            label="Merchant",
            value="Example Shop",
        ),
    ),
    irreversible=True,
    requested_at=now,
)
preview = guard.require_preview(manifest, request, now=now)
```

`SUBMIT`, `PURCHASE`, `SEND_MESSAGE`, `PERMISSION_CHANGE`, `IRREVERSIBLE`,
`UPLOAD`, `CREDENTIAL_USE`, and clipboard writes require approval by default.
Any action marked irreversible or carrying sensitive data also requires it.
Submissions, purchases, messages, permission changes, clipboard writes, and
irreversible operations must declare bounded, uniquely named
`BrowserActionReviewField` values from application-owned state. Render the
complete preview in application-owned UI outside the page. Protect the preview
as sensitive data because it can include entered text and review values.

An authenticated review service creates `BrowserActionApproval` for the exact
manifest, request, preview, session, tenant, actor, approver, issuance time, and
expiry. Configure a production `BrowserApprovalVerifier`; the static verifier
is only a deterministic example helper.

```python
authorization = guard.require_action(
    manifest,
    request,
    preview,
    approval=authenticated_exact_approval,
    now=now,
)
```

The guard recomputes the preview immediately before authorization. Preview or
request mutation, stale approval, context mismatch, unauthenticated approval,
and replay all fail closed. Action and approval identities are claimed
atomically. Dispatch the unchanged request and returned authorization directly
to a trusted actuator. Do not let the model reinterpret, broaden, or retry it.

## Control credentials and data movement

Direct cookie, browser-storage, and host-secret reads are always denied.
Credential use requires an opaque `credential_ref`, an authenticated target
origin, the exact observation, fresh approval, and a credential broker outside
model context. Raw credentials and host secrets cannot be carried through
`BrowserDataFlow`.

Every declared flow binds a source kind, optional source origin, destination
origin, content digest, and sensitivity. Cross-origin movement needs an exact
`BrowserOriginFlow` edge for that source kind; sensitive movement additionally
requires `allow_sensitive=True`. The action target must equal the flow
destination.

Clipboard reads/writes and local-file reads are separately disabled by default.
Uploads use `upload_grants`; local reads use `local_file_grants`. Each
`BrowserFileGrant` is content-bound and limits file reference, digest, media
type, size, destination, and expiry. File paths and bytes never belong in the
grant.

## Quarantine expected downloads

A download request must carry `BrowserExpectedDownload` before any bytes
arrive. The session policy must enable that exact media type and bound both the
expected and absolute byte limits. Configure a
`BrowserDownloadEvidenceVerifier`; after the authorized download completes,
pass authenticated exact broker evidence to `require_download()`:

```python
released = guard.require_download(
    manifest,
    download_authorization,
    quarantine_evidence,
    now=now,
)
```

The evidence must match the authorization, expected download ID, source origin,
media type, and size. Required quarantine and malware-scan evidence must be
present and clean. The returned result contains a one-way download reference
and content digest, not bytes. Continue to treat released content as untrusted
at its next boundary.

## Failure handling and deployment checklist

- Use `inspect_*`, `preview_action`, `authorize_action`, and `verify_download`
  when you need typed `BrowserIsolationResult` decisions. The corresponding
  `require_*` methods raise `BrowserIsolationError` on failure.
- Keep finding messages and references content-free. Store raw observations and
  previews only in access-controlled systems with suitable retention.
- Implement `BrowserAuthorizationStateStore.claim_many()` with a durable,
  linearizable shared transaction in multi-worker or multi-region deployments.
  State-store errors must fail closed.
- Re-enter the boundary after every redirect, new tab/window, frame navigation,
  origin or authentication change, permission prompt, upload, download, and
  service-worker-mediated side effect.
- Enforce origin, DNS/IP, protocol, redirect, egress, filesystem, clipboard,
  cookie, download, and profile controls in the browser/network sandbox as well
  as in application policy.

## Assumptions, limitations, and residual risk

- Trustrail cannot observe a browser. Security depends on instrumentation that
  truthfully reports pixels, DOM/accessibility state, frame and target origins,
  visibility, occlusion, enabled state, and action classification. A compromised
  broker can forge all of these fields.
- The library does not detect visual deception, OCR errors, homoglyphs, CAPTCHA
  manipulation, semantic prompt injection, or adversarial images. The typed
  boundary prevents page content from becoming authorization; it does not prove
  the model interpreted a page correctly.
- Host allowlisting cannot by itself stop DNS rebinding, redirects, proxy
  confusion, alternate IP representations, TOCTOU, or network-layer SSRF. Pin
  resolved destinations and enforce every connection and redirect at egress.
- HMAC signatures provide integrity only while the shared key is protected.
  They do not authenticate a compromised issuer. Use a protected signing
  service, key rotation, least privilege, synchronized clocks, and audit.
- Approval does not prove understanding or make a harmful action safe. The UI
  must be non-spoofable and accessible, show every material field, authenticate
  the approver, and remain independent of page-controlled overlays.
- Malware scanning has false positives and negatives. Keep downloads
  quarantined, restrict parsers, patch viewers, and apply destination-specific
  validation even after release.
- Single-use authorization cannot reverse an already completed purchase,
  message, disclosure, permission change, or upload. Use downstream idempotency,
  service-side authorization, value/rate limits, transactions, and rollback
  where the domain supports them.

See the runnable
[`browser_computer_use_isolation.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/browser_computer_use_isolation.py)
example. These controls align with the OWASP AI Agent Security Cheat Sheet and
OWASP LLM01 prompt-injection guidance; see the [OWASP mapping](../owasp-mapping.md).
