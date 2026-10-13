# Synthetic case inventory

On macOS, `inventory/<suite>.darwin.tsv` replaces the base file where cases
differ by platform (no `/proc`, BSD `script` exit status). Each
`inventory/<suite>.tsv` row contains `suite<TAB>name<TAB>kind<TAB>expected`.
Kinds are `check` (expected exit status), `assert` (zero status) and `decision`
(`allow` or `deny`). Repeated case names receive an encounter-order `#2`,
`#3`, etc. suffix. The key is `suite/name`, including any suffix. Later Go
parity tests must reference these keys and preserve each case's setup and
expectation, not merely compare totals.

Run `bash tests/inventory.sh --check` on Linux or macOS for the four synthetic
suites. Run `bash tests/inventory.sh --write` only after intentionally changing
a test, review every diff, and explain additions or changes in the commit.
Use `--suite libsecret` in an isolated Secret Service session or `--suite
keychain` on macOS with a disposable Keychain. Never run provider suites on a
real store. The keychain inventory is initially absent: CI uploads it as an
artifact. Commit the downloaded artifact after review, then require
`SECRET_INVENTORY_STRICT=1` in CI. `SECRET_INVENTORY_DIR` permits generating an
inventory on a read-only repository mount.
