# Security

This crate is supported only as used by scryer-media's own applications. Report vulnerabilities
privately through the affected first-party application's GitHub Security
Advisories. Do not post vulnerability details in public issues or pull requests.

The embedding application is the trust boundary: it decides which release
repository, workflow and tag an upgrade must come from, and when an upgrade may
run. This crate verifies that the manifest was signed by that identity, that
every downloaded artifact matches what the manifest signed, and that an archive
writes nothing outside the directory it is extracted into.
