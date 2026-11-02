# ESC-04: Uploaded photos kept their EXIF metadata, GPS coordinates included

| | |
|---|---|
| Severity | **Medium**, CVSS 3.1 4.3 (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`) |
| Weakness | CWE-212 Improper Removal of Sensitive Information Before Storage or Transfer |
| Affected | Yamesi `15f0bf8` (`backend/src/common/image-upload.ts`, piece photos and petty-cash receipts) |
| Status | Fixed: yamesi `f606dad` |

## Description

Uploads were checked by their magic bytes and stored exactly as received. A photo taken with a phone carries
EXIF: GPS coordinates, the device model and the capture time. Day 1 removed that metadata from the photos
committed to the repository ([ESC-10](ESC-10-gps-in-published-photo.md)). The same leak was still open at
runtime for every new photo an admin uploads.

## Evidence (2026-11-02)

```text
crafted JPEG (catalog photo + EXIF APP1 with a GPS IFD): has GPS = true
upload JPEG with GPS -> 200
stored photo has GPS: true   content-type image/jpeg
```

## Impact

Every user who can see the catalog, sellers included, downloads the coordinates of where each photo was
taken. In a small business that is often the owner's home or the workshop where gold is kept. Exposure is
limited to authenticated users, who receive short-lived presigned URLs.

## Fix

`requireImage` now returns the bytes to store: the same image without metadata. The stripping uses no new
dependency and works at the container level, without decoding pixels:

- JPEG: drops every APPn segment except JFIF, the ICC color profile and Adobe's color transform. Comments
  go too. The EXIF block is replaced by one holding only the orientation, so a photo taken sideways still
  displays upright.
- PNG: drops `eXIf`, `tEXt`, `zTXt`, `iTXt`, `tIME`, and anything after `IEND`.
- WebP: drops the `EXIF` and `XMP ` chunks, clears their flags in `VP8X`, and rewrites the RIFF size.
- A file whose structure does not parse is refused (see [ESC-06](ESC-06-jpeg-prefixed-html-accepted.md)).

Re-encoding with an image library would also work and would drop anything hidden in the pixel data. It
was set aside to keep the image small and free of native dependencies.

## Regression tests

- Yamesi `backend/test/unit/image-upload.spec.ts`: six cases, all of which fail with the stripping disabled
  (GPS removed with the scan data intact, orientation kept, comment dropped, PNG text chunks, WebP chunks
  and flags, truncated file).
- Yamesi `backend/test/e2e/inventory.e2e-spec.ts`: the stored object of an uploaded phone photo has no EXIF.
- [`attacks/yamesi.test.mjs`](../attacks/yamesi.test.mjs): the photo served from the bucket has no GPS.
