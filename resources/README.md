# Mute Agent artwork

These are the approved Mute Agent logo resources for `secret`.

- `logo.svg`: 512 px tile icon, used in the repository README header and copied
  to `packaging/mcpb/icon.svg` as the packaging vector reference.
- `logo-mark.svg`: transparent violet mark (`#5B3DF5`) for light backgrounds.
- `logo-mark-dark.svg`: transparent cream mark (`#F4EFE6`) for dark backgrounds.
- `logo-256.png`: reviewed 256 x 256 render of `logo.svg`, copied to
  `packaging/mcpb/icon.png` for the Desktop MCPB manifest and bundle.
- `logo-512.png`: reviewed 512 x 512 render of `logo.svg` for larger raster use.

The tile uses a `#6A4BFF` to `#2B1690` gradient with a white mark. PNGs are
reviewed, committed bytes rendered from the SVG, not regenerated in builds.

When updating the artwork, replace the SVG and PNGs together, including the
transparent mark variants as needed. Run `python3 -I scripts/sync-branding.py`
from the checkout root, then `python3 -I scripts/sync-branding.py --check` and
`python3 -I tests/test-mcpb.py`. Visually review at 16, 32, 88 and 256 px in both
light and dark contexts before accepting the update.
