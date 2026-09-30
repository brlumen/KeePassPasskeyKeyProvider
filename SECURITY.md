# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/brlumen/KeePassPasskeyKeyProvider/security/advisories/new), not in public issues.

Include the plugin version, Windows and KeePass versions, the authenticator type and the steps to reproduce. You should get a reply within a week. Once a fix is released, the advisory is published with credit to the reporter, unless you prefer otherwise.

## Supported versions

Only the latest release gets security fixes.

## Scope

In scope: anything that lets an attacker open a database, learn the database key or a device/phrase secret, make the plugin accept forged device records, or lock the user out in a way not described in the README.

Known limitations are listed in the README under "Security model and limitations" (for example, a revoked device with an old copy of the database). They are not vulnerabilities unless you find a way to go beyond what is described there.

Out of scope: vulnerabilities in KeePass, Windows WebAuthn, Windows Hello or authenticator firmware — report them to their vendors.

## Verifying a release

Release DLLs are built by GitHub Actions from the tagged source and the build is reproducible. Verify the origin with `gh attestation verify KeePassPasskeyKeyProvider.dll --repo brlumen/KeePassPasskeyKeyProvider`, or build the tag yourself against KeePass 2.58 (see the README) and compare the SHA-256.
