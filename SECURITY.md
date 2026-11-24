# Security

## Status

cairn is a research preview. It has had no external review and must not be used to protect
anything of value. The known limits are listed in the README under "Status and limits" and in
ARCHITECTURE.md section 11; they are not vulnerabilities to report, they are the roadmap.

## Reporting a vulnerability

Report anything that contradicts what the documentation claims, for example:

- a signature or certificate that verifies but was not produced by an authorized quorum;
- key or share material reaching a party the documentation says cannot see it;
- a rejected attempt revealing more than one bit;
- a node accepting a peer it should not, or a frame from the wrong sender;
- a way for fewer than four signers to block signing.

Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a
vulnerability"). If that is not available to you, open an issue that says only that you have a
security report, without details, and you will be contacted.

Please include the commit, the commands you ran and what you observed.

## Scope

In scope: everything in this repository. Out of scope: MP-SPDZ itself, pqc-sidecar and the
verifier packages, which have their own maintainers; the clear-text reference worker's lack of
secrecy, which is by design and documented.
