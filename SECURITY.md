# EG security boundary

Only EG may make task progress and terminal decisions. Every governed mutation
must use the trusted executor after PRE; unrelated shell processes, notebook
commands and host root cannot be intercepted solely by a user-space API.
Fail closed on missing executor, absent or invalid receipt, lost audit
integrity, stale gates, missing configuration or unsupported capabilities.
Store keys and task state in external separately protected persistent storage.
Do not commit or publish credentials, audit databases, evidence, or signing keys.
