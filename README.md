# application-updater

The signed in-application upgrade core for
[Scryer](https://github.com/scryer-media/scryer) and the other
[scryer-media](https://github.com/scryer-media) first-party applications.

**This library is built only for scryer-media's own applications. Any other use is unsupported.
Your mileage may vary (YMMV).** APIs may change to meet first-party needs without
third-party compatibility guarantees. External support and feature requests
are not accepted.

## What it provides

- Validation of the signed release manifest that names a release's upgrade
  artifacts: tag binding, canonical download URLs, sizes, BLAKE3 hashes, and
  the exact member list of every archive.
- Two manifest generations. **v1 is frozen**: shipped clients reject any value
  they do not recognize, so nothing may ever be added to it. **v2** is
  forward-tolerant — unknown fields are ignored, and artifacts of a kind the
  client does not know are kept but never selected — while everything the client
  does understand is validated as strictly as v1. Clients read v2 first and use
  v1 only when a release has no v2 asset; any other v2 failure is fatal.
- Signature verification of the manifest through
  [artifact-trust](https://github.com/scryer-media/artifact-trust), against the
  release workflow identity the host supplies.
- Installation classification: which layouts may upgrade themselves, which are
  owned by a package manager, a container or an installer, and why.
- Capped download, hash verification, archive validation and extraction that
  accepts regular files (and, for application bundles, directories) only.
- Promotion with rollback for portable installs and macOS application bundles,
  and the plan and temporary helper that replace a running Windows install.
- A durable journal, so an upgrade interrupted at any point is either finished
  or undone on the next start.

Everything product-specific — names, the release repository and workflow,
asset filenames, schema identifiers, environment markers — arrives through
`ProductDescriptor`. The host keeps its job records, progress reporting,
restart control and free-space accounting, and passes them in per call.

The journal, helper-plan and manifest formats are wire contracts: a helper from
one release must read a plan or journal written by another.

## Consumption

First-party applications consume this repository through **signed version tags**.
It is not published to crates.io; the manifest sets `publish = false`.

```toml
[dependencies]
application-updater = { git = "https://github.com/scryer-media/application-updater.git", tag = "v0.1.0" }
```

Tags are signed, annotated, and immutable: never move an existing version tag.
Commit the consumer's `Cargo.lock` so it records the exact resolved commit.
Do not track a moving branch.

The `test-seams` feature exposes a seam that can stand in for signature
verification. It exists for a host crate's own tests; enable it only as a
dev-dependency feature, never in a shipped build.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo nextest run --locked --no-fail-fast
```

The tests are offline and work in temporary directories. Nothing here may be
run against a live installation.

## License

GPL-3.0-only (GNU General Public License version 3). See [LICENSE](LICENSE).
The unsupported-use policy does not restrict rights granted by that license.
