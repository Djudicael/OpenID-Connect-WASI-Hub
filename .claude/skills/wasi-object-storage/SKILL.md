---
name: wasi-object-storage
description: Add S3-compatible object storage (RustFS, MinIO, AWS S3) to the OpenID Connect WASI Hub's WASI 0.3 (P3 async) components using aws-sdk-s3 with a custom connector over oidc-wasi-http. The Hub does not use object storage yet; read this before introducing it (for example realm theme assets or export archives). Covers the storage client, uploads, presigned URLs, bucket provisioning, configuration, and tests. Do not use rust-s3 or reqwest-based clients in WASI code.
---

Read `../../../.agents/skills/wasi-object-storage/SKILL.md` completely and follow it. Treat that file (and its `references/` folder) as the canonical, model-independent skill definition.
