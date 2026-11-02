# ESC-06: A file that only started like a JPEG was accepted as a photo

| | |
|---|---|
| Severity | **Informational** (no exploitable impact found) |
| Weakness | CWE-434 Unrestricted Upload of File with Dangerous Type (mitigated) |
| Affected | Yamesi `15f0bf8` (`backend/src/common/image-upload.ts`) |
| Status | Fixed: yamesi `f606dad` |

## Description

The upload check looked at the first three bytes only. `FF D8 FF` followed by an HTML page with a script
passed as a JPEG and was stored.

## Evidence (2026-11-02)

```text
upload FF D8 FF + "<html><script>alert(document.domain)</script></html>" as photo.html (text/html) -> 200
served from the bucket as: image/jpeg, no X-Content-Type-Options, body contains <script>
```

## Why it is informational

The bucket serves the object as `image/jpeg` from its own origin (port 9002), and the API never echoes it.
Browsers do not render an `image/*` response as HTML, so no script ran. The file was junk in the catalog,
not a working attack.

## Fix

The metadata stripping added for [ESC-04](ESC-04-uploaded-photos-keep-gps.md) walks the file's structure, and
a file that does not parse as the image it claims to be is refused with `INVALID_IMAGE`. This file now gets
400.

Residual risk, accepted: a real, well-formed JPEG with extra bytes appended after its image data still
passes, because those bytes are copied untouched. They are served as `image/jpeg` like the rest.

## Regression tests

- Yamesi `backend/test/unit/image-upload.spec.ts`: a JPEG-prefixed HTML file and a truncated JPEG are refused.
- [`attacks/yamesi.test.mjs`](../attacks/yamesi.test.mjs): the upload gets 400 from the running stack.
