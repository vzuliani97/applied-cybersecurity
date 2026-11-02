# ESC-10: A catalog photo in the public repository carried exact GPS coordinates

| | |
|---|---|
| Severity | **Medium**, CVSS 3.1 5.3 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) |
| Weakness | CWE-212 Improper Removal of Sensitive Information Before Storage or Transfer |
| Affected | Yamesi `backend/demo-assets/pieces/` before `77e8993` |
| Status | Fixed 2026-11-01: yamesi `77e8993`, then the history was rewritten so the original file is gone |

## Description

A review of the published repository found one catalog photo with EXIF holding exact GPS coordinates, the
phone model and the capture time. More than 80 published images carried camera or editing-software data.

## Fix

- Metadata (EXIF, XMP, IPTC) was removed from every published image in all repositories.
- The file was rewritten out of Yamesi's history, with a full local backup taken first and a force-push. A
  clean `main` only removes the file from new checkouts; the old blob would still be reachable in the history.
- The coordinates themselves are not reproduced in this report.

## Regression tests

`scripts/image-metadata.mjs` runs in each repository's CI and fails if any committed image carries GPS,
device, author or location metadata. Photos uploaded at runtime had the same problem, see
[ESC-04](ESC-04-uploaded-photos-keep-gps.md).
