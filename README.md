# KeePassPasskeyKeyProvider

A KeePass 2.x plugin that opens a password database with a passkey — a hardware FIDO2 security key, a phone or tablet (via QR code) or Windows Hello. It works through the built-in Windows **WebAuthn API** and the **hmac-secret / PRF** extension. No drivers, third-party libraries or administrator rights required.

Not to be confused with the [KeePassPasskey](https://github.com/yusei36/KeePassPasskey) plugin, which stores website passkeys in KeePass. This plugin uses a passkey as a master key component.

## Features

- **Multiple devices per database.** For example, a YubiKey, a phone and Windows Hello — any of them opens the database.
- **Adding and removing devices** on the "FIDO2" tab in the database settings. Other devices do not need to be re-registered.
- **Device revocation.** On removal the database key is replaced, and the removed device will no longer open its new versions (see "Security model and limitations").
- **Recovery phrase** of 12 words (BIP39) — a fallback when no devices are at hand.
- **Master key change that keeps the devices** and the recovery phrase.
- **No files next to the database:** everything needed is stored in the `.kdbx` file, the credential — on the device itself.
- **Compatible with a password and a key file:** they can be combined with a device in a composite master key.
- **Signed device records:** a header forged without the database key is rejected.
- **Diagnostics:** WebAuthn call log and PRF support check.

## Requirements

- Windows 11 22H2 or later (WebAuthn API v4+). Windows 10 only if its WebAuthn API reports v4+ (check in `Tools → KeePassPasskeyKeyProvider`).
- KeePass 2.52 or later (tested with 2.58), KDBX 4 database format (KeePass selects it automatically).
- An authenticator with hmac-secret/PRF support:
  - **hardware FIDO2 security key** — YubiKey 5, SoloKey, Nitrokey 3, Google Titan, etc.;
  - **phone or tablet** via QR code (the computer needs Bluetooth). Tested with Google Password Manager on Android; other passkey providers must support PRF;
  - **Windows Hello** — Windows 11 24H2/25H2 with update KB5077181 (build ≥ 26100.7840 / 26200.7840).

## Installation

1. Download `KeePassPasskeyKeyProvider.dll` from [Releases](https://github.com/brlumen/KeePassPasskeyKeyProvider/releases).
2. Put it into the KeePass `Plugins` folder (for example, `C:\Program Files\KeePass Password Safe 2\Plugins\KeePassPasskeyKeyProvider\`).
3. Restart KeePass.

## Usage

### Creating a database or changing the master key

1. `File → New` or `File → Change Master Key`.
2. Check "Key file/provider" (under "Show expert options") and select **Passkey Key Provider (Windows WebAuthn)**. You can keep the password — it becomes a second factor.
3. In the plugin window, enter a device name (for example, "Blue YubiKey").
4. In the "Windows Security" window, choose an authenticator:
   - **FIDO2 security key** — PIN and a touch of the key;
   - **phone** — "Use another device" → QR code → confirmation on the phone;
   - **Windows Hello** — PIN or biometrics.
5. For a new database, the database settings open on the **FIDO2** tab; after changing the master key, open `File → Database Settings → FIDO2` yourself. Add a second device or create a recovery phrase — otherwise, if the only device is lost, the database becomes inaccessible.

When changing the master key of a database that already has devices, the plugin asks whether to keep them. If kept, they and the recovery phrase continue to open the database without re-registration; if not, they and the recovery phrase are removed from the database, and only the new device will be able to open it. Changing to a master key without this provider removes all device records and the recovery phrase.

### Opening a database

Select the same provider and confirm with any registered device. Windows offers only the credentials of this database.

If authentication fails or WebAuthn is unavailable, and the database has a recovery phrase, the plugin offers to open the database with it.

### "FIDO2" tab (`File → Database Settings`)

- **Add device** — a new passkey for this database; the database is saved immediately.
- **Remove selected device** — the database key is replaced (see "Security model"), the database is saved. The last device cannot be removed.
- **Create / replace / remove recovery phrase.** The phrase is shown once; you must write it down and confirm it. Replacing and removing also replace the database key.
- **Windows Hello cleanup…** — opens the cleanup window (see below).

### `Tools → KeePassPasskeyKeyProvider` window

- Windows WebAuthn API version;
- **Windows Hello credentials not found in any known database.** Each credential is looked up in open databases, in KeePass's recently used files and in the database at the path saved in the credential. A database that was moved, renamed or saved elsewhere is not detected, so nothing is checked in advance: delete only credentials you are sure are unused — a database whose only device was a deleted credential (and that has no recovery phrase) can no longer be opened. The plugin never deletes credentials on its own: the credential of a device removed from a database may be needed to open an old backup;
- **PRF diagnostics** — creates a test credential, checks that the authenticator returns a PRF secret and that it is repeatable, and shows the WebAuthn call log. The secret itself is not written to the log. The test credential stays on the authenticator (see "Security model and limitations").

## How it works

- **Database key K** — 32 random bytes; KeePass uses it as a master key component.
- **Device** — a discoverable credential (passkey) with the hmac-secret/PRF extension. For a fixed salt it returns a secret S_i that does not leave the authenticator without user confirmation (user verification is required: PIN, biometrics).
- **Wrap for an owner** (a device or the recovery phrase): the owner has its own P‑256 key pair; its private key d_i is stored as d_i ⊕ S_i, and K is encrypted to the public key (ECIES: ephemeral ECDH + SHA‑256). Without the owner's secret a wrap is useless.
- **Database signing key.** Each database has an ECDSA P‑256 key pair. The verification key VK is stored with the records; the signing key SK is stored in the encrypted part of the database (`CustomData`), and every change of the records is signed with it.
- **Owner tag.** When a device or the phrase is added, its wrap gets a tag HMAC‑SHA256(S_i, label ‖ VK) that binds the owner to this database's VK.
- **Header record** (`PublicCustomData` of the unencrypted KDBX 4 header, format v4): VK, device records (credential ID, wrap with owner tag, name), the optional recovery phrase wrap and the signature.
- **Opening:** GetAssertion by the credential IDs from the records → S_i → the owner tag must match VK → d_i → K → the signature of the records must verify with VK. Only then K is passed to KeePass.
- **Removing a device or the phrase** = rotation: a new K' is encrypted to the public keys of the remaining devices and the phrase — without the devices themselves; the master key is replaced (password and key file are kept); the database is saved. SK and the owner tags stay the same. New and old wraps are unrelated, so a removed device learns nothing about K' from old copies of the file.
- **Recovery phrase:** 128 bits of entropy as 12 BIP39 words (English wordlist, with checksum). R = HMAC‑SHA256(entropy, label); the phrase is an owner like a device, with R as its secret.
- **Import and synchronization:** merging another database into this one does not replace its records or signing key — the plugin restores them before saving.
- **PRF salt and RP ID** (`keepass-fido2.local`) are fixed: the secret depends on them, and changing them would make existing databases impossible to open.

There are no files next to the database: a copy of the `.kdbx` contains everything needed except the devices themselves.

## Security model and limitations

- **Forged headers.** Anyone with write access to the file can replace its header. Someone who never had the database key cannot build a database that your device or phrase opens: a copied wrap is bound to your VK by the owner tag, and signing for that VK requires SK from inside the database.
- **A revoked party with an old copy is not stopped.** Anyone who once had K — for example, the holder of a removed device or phrase with a copy of the database from before the removal — can extract SK from that copy, since rotation keeps SK. If they can write the file, they can forge records that your devices accept, or roll the file back to a copy from before the removal — the removed device then regains access to everything saved after that. A password in the composite master key prevents forging by anyone who does not know it: use one for databases in cloud or shared folders.
- **Revocation only works forward.** A removed device will not open the current database or its later versions, but will open copies made before the removal (backups, version history in the cloud). If it must not have access to the secrets in the database, change them.
- **The header is readable without the key:** device names (the default name includes the computer name), the number of devices and whether a recovery phrase exists. The credential on a security key or phone stores the database file name and full path.
- **A single device without a recovery phrase** means a risk of losing the database if the device breaks or is lost. The plugin warns about this on the FIDO2 tab.
- **The recovery phrase replaces a device:** together with the password or key file, if the master key has them, it opens the database. Keep it offline.
- **Discoverable credential slots.** Each database and device uses a discoverable credential slot on a security key, and their number is limited. PRF diagnostics leaves a test credential on the authenticator: delete it in `Tools → KeePassPasskeyKeyProvider` or `Settings → Accounts → Passkeys` (Windows Hello), with the manufacturer's tool (e.g. Yubico Authenticator, `ykman`) or in a browser's security key settings. Do not reset the security key in Windows Settings: a reset deletes all its credentials, including those that open your databases.
- **Windows does not bind the RP ID to an application.** Any program running under your account can request the same PRF secret — but only after your confirmation (PIN, touch, biometrics). Any local program can also list and delete Windows Hello credentials.
- **Windows Hello** is protected the same way as your Windows account (PIN, TPM).
- **A passkey on a phone is synced** via the provider account (Google, Apple, etc.): its security equals the security of that account. The database path stored in the credential is synced too.
- **Attestation is not verified:** any authenticator with PRF support is accepted.

## Troubleshooting

**"Windows WebAuthn API is not available"** — requires WebAuthn API v4+ (Windows 11 22H2 or later) and the file `C:\Windows\System32\webauthn.dll`.

**"The authenticator does not support hmac-secret/PRF" on creation**
- an old U2F key without hmac-secret — a FIDO2 key is required (YubiKey 5 and newer);
- Windows Hello without KB5077181 — update Windows 11 to build ≥ 26100.7840 / 26200.7840;
- a phone password manager without PRF (Samsung Pass, etc.) — use one with PRF support (e.g. Google Password Manager).

**"The database header has no FIDO2 device records"** — the database was not saved after the key was created, or its header is corrupted. Open a backup.

**"The device records of this database are not authentic"** — the owner tag or the signature did not match: the header was modified or taken from another database. Open a backup and check who can write the file.

**"The authenticator presented a credential not registered in this database"** — a device removed from the database or created for another database was chosen.

**The plugin is not in the key provider list** — disable `Tools → Options → Security → Enter master key on secure desktop`: WebAuthn dialogs can't be shown there.

**The "Windows Security" window does not appear** — check whether it is hidden behind other windows; for a phone the computer needs Bluetooth.

You can check an authenticator in `Tools → KeePassPasskeyKeyProvider → PRF diagnostics`: it shows whether it enabled PRF (`bPrfEnabled`, WebAuthn API v6+), returned a secret (`pHmacSecret`) and whether the secret matches on repeat.

## Building

```powershell
git clone https://github.com/brlumen/KeePassPasskeyKeyProvider.git
cd KeePassPasskeyKeyProvider
dotnet build KeePassPasskeyKeyProvider.csproj -c Release   # → bin\Release\KeePassPasskeyKeyProvider.dll
```

- .NET Framework 4.7.2 Developer Pack (targeting pack) and Visual Studio 2019+ or the `dotnet` SDK. No NuGet packages.
- KeePass must be installed: `KeePass.exe` is referenced from `C:\Program Files\KeePass Password Safe 2\`. For another location, pass the folder with a trailing backslash: `dotnet build ... -p:KeePassDir=D:\KeePass\`. A backslash before a closing quote escapes the quote, so for a path with spaces double it: `-p:KeePassDir="C:\My Apps\KeePass\\"`.
- The Debug configuration builds the DLL directly into KeePass's `Plugins\KeePassPasskeyKeyProvider\` (write access to that folder is required, KeePass must be closed).

## Code structure

```
src/
├── KeePassPasskeyKeyProviderExt.cs        — plugin entry point: provider, menu, FIDO2 tab, KeePass events
├── FIDO2KeyProvider.cs         — Key Provider: key creation, opening, rotation
├── DeviceKeyStore.cs           — signed device and phrase records in the KDBX header
├── KeyWrap.cs                  — wrapping of the database key for a device or the phrase (ECIES, owner tag)
├── SigningKey.cs               — database ECDSA key pair that signs the records
├── RecoveryPhrase.cs           — BIP39 recovery phrase
├── HelloCredentialAudit.cs     — matching Windows Hello credentials to databases
├── FIDO2DevicesControl.cs      — "FIDO2" tab in the database settings
├── FIDO2OptionsForm.cs         — "Tools → KeePassPasskeyKeyProvider" window
├── FIDO2DiagnosticsForm.cs     — PRF diagnostics
├── DeviceNameForm.cs, RecoveryPhrase*Form.cs, BusyIndicator.cs — dialogs
├── Strings.cs, Strings*.resx, EmbeddedResourceManager.cs — UI strings (English, Russian)
└── WebAuthn/
    ├── WebAuthnApi.cs          — P/Invoke and webauthn.dll structures
    └── WebAuthnHelper.cs       — MakeCredential / GetAssertion with PRF, Windows Hello credentials
```

API documentation: [Windows WebAuthn](https://learn.microsoft.com/windows/win32/api/webauthn/), header [webauthn.h](https://github.com/microsoft/webauthn/blob/master/webauthn.h), [hmac-secret specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension), [KeePass plugins](https://keepass.info/help/v2_dev/plg_index.html).

## License

[MIT](LICENSE)

`src/bip39-english.txt` is the BIP-0039 English wordlist from https://github.com/bitcoin/bips.
