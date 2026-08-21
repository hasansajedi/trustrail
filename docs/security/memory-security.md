# Persistent memory security

Long-lived memory is a security boundary. An attacker can ask an agent to remember
malicious instructions, false identity claims, credentials, or preferences that
change later sessions. Treat model-proposed memory as untrusted even when it
appears to quote the user.

## Required controls

1. Keep the memory backend inaccessible to the model and its tools by default.
2. Call `authorize_memory_write()` before every persistent write.
3. Bind approval to the authenticated user, tenant, target key, and session outside
   the model.
4. Present the normalized/redacted value and its classification to the approver.
5. Record the approval decision separately without logging the memory content.
6. Re-scan memory at `MEMORY_READ` before placing it in an LLM request.
7. Support expiry, user inspection, correction, and deletion.

`MEM-001` returns `REQUIRE_APPROVAL` for persistent `general`, `preference`,
`profile`, and `instruction` writes. Credential- or secret-like memory is blocked.
Prompt-injection and sensitive-data policies run before classification, so an
approval cannot override a security block.

The classifier is a policy signal, not proof that the proposed fact is accurate or
belongs to the current user. Authorization and ownership checks must use trusted
application state. Never accept an approval token, trust label, or persistence flag
from model-generated content.

Audit events contain the stage, action, input length, and finding identifiers, not
the proposed memory. The initial event records `required`; a second event records
`approved`, `denied`, `missing_provider`, or `provider_error`, together with the
content-free classification. The approval provider necessarily receives the safe
candidate for human review; protect that channel as sensitive application data.
