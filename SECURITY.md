# Security

## Status

cairn has had no external review. Do not use it to protect anything of value until it has.
The committee engine is the one to rely on; the tower engine is research. The known limits
are in the README under "What it is not, yet" and in docs/BLOCKERS.md; they are not
vulnerabilities to report, they are the roadmap.

## Supported versions

Only the latest release gets fixes. There are no back-ports.

## Reporting a vulnerability

Report anything that contradicts what the documentation claims, for example:

- a signature or certificate that verifies but was not produced by an authorized quorum;
- key or share material reaching a party the documentation says cannot see it;
- a rejected attempt revealing more than one bit;
- a node accepting a peer it should not, or a frame from the wrong sender;
- a way for fewer than four signers to block signing.

Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a
vulnerability"), or write to <rick@dytallix.com>. Please do not put details in a public issue.

Please include the commit, the commands you ran and what you observed.

This is one person's project with no funding. Expect an answer within a week, and a fix or a
documented limit in the next release. You will be credited in the release notes unless you
ask not to be. There is no bounty.

## Checking a release

Release archives have SHA-256 checksums and, after 0.7.1, a signed build provenance
statement. docs/RELEASING.md shows how to verify it and how to rebuild a release from its tag
and compare.

## Scope

In scope: everything in this repository. Out of scope: MP-SPDZ itself, pqc-sidecar and the
verifier packages, which have their own maintainers; the clear-text reference worker's lack of
secrecy, which is by design and documented.
