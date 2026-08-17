# Cross-machine transfer evidence

## Result

The exact Teamwork v1.0.0 release passed one real Kubuntu-to-macOS transfer on 2026-08-17 UTC.

- Source commit: `d74b55d74956ce304ee495747729d502d15936d7`
- Archive SHA-256: `d00ea706fb58455635d64c560acadcdbe16ae0910c4828fb425bf9d6c51bee34`
- Payload ID: `211956c1-f46c-4842-af36-155425a3c52d`
- Producer: `linux-producer` / `cross-machine-e2e`
- Consumer: `macos-consumer` / `cross-machine-e2e`
- Revision: ready 1 on Kubuntu to ready 2 on macOS
- Machine-readable report: `certification-results/cross-machine-kubuntu-to-macos.json`

## Workflow proved

1. A fresh Kubuntu Git fixture was committed with one safe pending action.
2. The release artifact and packaged verifier were checked on the producer.
3. Packaged `teamwork-handoff` prepared, curated, sealed, and verified ready revision 1.
4. `.teamwork/` was ignored and untracked.
5. The complete Git fixture, including `.git/` and `.teamwork/`, crossed a hash-checked relay.
6. The fixture was extracted at a different absolute path on the macOS VM.
7. The same exact release and packaged `teamwork-resume` verified checksums, recovered the relocated root, read nine documents, and emitted the producer identity and first safe action.
8. The macOS consumer completed and committed the safe action.
9. Packaged handoff refreshed the existing payload, preserved its ID, incremented revision 1 to 2, and resealed it ready.
10. The final repository was clean and the payload remained ignored/untracked.

Producer runtime was Linux kernel 7.0.0-28-generic, Python 3.14.4, and Git 2.53.0. Consumer runtime was Darwin 25.6.0, Python 3.14.7, and Apple Git 2.50.1.

## Provenance caveat

One producer-home, nonrepository guidance source was unavailable on the destination and was reported as missing. This is expected cross-machine provenance behavior: the consumer did not silently treat the absent source as unchanged. The repository `AGENTS.md` remained present, unchanged, and readable.

## Claim boundary

This certifies one exact artifact, payload, route, and pair of environments. The relay did not test every archive utility, network transport, permission model, filesystem, or harness. Both disposable VM fixtures and the local relay were removed after the sanitized evidence report was independently validated.
