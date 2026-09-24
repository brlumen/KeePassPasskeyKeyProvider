# KeePassPasskeyKeyProvider

A KeePass 2.x plugin that opens a password database with a passkey — a hardware FIDO2 security key, a phone or tablet (via QR code) or Windows Hello. It works through the built-in Windows **WebAuthn API** and the **hmac-secret / PRF** extension. No drivers, third-party libraries or administrator rights required.

## Features

- **Multiple devices per database.** For example, a YubiKey, a phone and Windows Hello — any of them opens the database.
- **Adding and removing devices** on the "FIDO2" tab in the database settings. Other devices do not need to be re-registered.
- **Device revocation.** On removal the database key is replaced, and the removed device will no longer open its new versions.
- **Recovery phrase** of 12 words (BIP39) — a fallback when no devices are at hand.
- **Master key change that keeps the devices.**
- **No files next to the database:** everything needed is stored in the `.kdbx` header, the credential — on the device itself.
- **Compatible with a password and a key file:** they can be combined with a device in a composite master key.
- **Diagnostics:** WebAuthn call log and PRF support check.

## Requirements

- Windows 10 22H2 or Windows 11 (WebAuthn API v4+).
- KeePass 2.x, KDBX 4 database format (KeePass selects it automatically).
- An authenticator with hmac-secret/PRF support:
  - **hardware FIDO2 security key** — YubiKey 5, SoloKey, Nitrokey 3, Google Titan, etc.;
  - **phone or tablet (Android, iOS)** via QR code (Windows 11 23H2+), with a passkey provider that supports PRF (e.g. Google Password Manager on Android 14+);
  - **Windows Hello** — Windows 11 24H2/25H2 with update KB5077181 (build ≥ 26100.7840 / 26200.7840).

## Installation

1. Download `KeePassPasskeyKeyProvider.dll` from [Releases](https://github.com/brlumen/KeePassPasskeyKeyProvider/releases).
2. Put it into the KeePass `Plugins` folder (for example, `C:\Program Files\KeePass Password Safe 2\Plugins\KeePassPasskeyKeyProvider\`).
3. Restart KeePass.

## Usage

### Creating a database or changing the master key

1. `File → New` or `File → Change Master Key`.
2. Check "Key file / provider" and select **FIDO2 Key Provider (Windows WebAuthn)**. You can keep the password — it becomes a second factor.
3. In the plugin window, enter a device name (for example, "Blue YubiKey").
4. In the "Windows Security" window, choose an authenticator:
   - **FIDO2 security key** — PIN and a touch of the key;
   - **phone** — "Use another device" → QR code → confirmation on the phone;
   - **Windows Hello** — PIN or biometrics.
5. The database settings open on the **FIDO2** tab. Add a second device or create a recovery phrase — otherwise, if the only device is lost, the database becomes inaccessible.

When changing the master key of a database that already has devices, the plugin asks whether to keep them. If kept, they continue to open the database without re-registration; if not, they are removed from the database, and only the new device will be able to open it.

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
- **Windows Hello credentials not linked to existing databases.** The plugin does not delete them on its own: the credential of a device removed from a database may be needed to open an old backup. Only those whose database was not found at its path are checked; delete the others deliberately;
- **PRF diagnostics** — creates a test credential, checks that the authenticator returns a PRF secret and that it is repeatable, and shows the WebAuthn call log. The secret itself is not written to the log.

## How it works

- **Database key K** — 32 random bytes; KeePass uses it as a master key component.
- **Device** — a discoverable credential (passkey) with the hmac-secret/PRF extension. For a fixed salt it returns a secret PRF_i that does not leave the authenticator without user confirmation (user verification is required: PIN, biometrics).
- **Device record** in the database header (the unencrypted part of the KDBX 4 header, `PublicCustomData`): credential ID, name and K ⊕ PRF_i. Without the device this record is useless.
- **Opening:** GetAssertion by the credential IDs from the records → PRF_i → K = (K ⊕ PRF_i) ⊕ PRF_i.
- **Removing a device** = rotation: a new K'; the wrapped keys of the remaining devices and the phrase are recomputed without the devices themselves; the master key is replaced (password and key file are kept); the database is saved.
- **Recovery phrase:** 128 bits of entropy as 12 BIP39 words (English wordlist, with checksum). R = HMAC‑SHA256(entropy, label); the header stores K ⊕ R.
- **PRF salt and RP ID** (`keepass-fido2.local`) are fixed: the secret depends on them, and changing them would make existing databases impossible to open.

There are no files next to the database: a copy of the `.kdbx` contains everything needed except the devices themselves.

## Security model and limitations

- **Revocation only works forward.** A removed device will not open the current database or its later versions, but will open copies made before the removal (backups, version history in the cloud). If it must not have access to the secrets in the database, change them.
- **A single device without a recovery phrase** means a risk of losing the database if the device breaks or is lost. The plugin warns about this on the FIDO2 tab.
- **The recovery phrase is as strong as the master key:** keep it offline.
- **Windows does not bind the RP ID to an application.** Any program running under your account can request the same PRF secret — but only after your confirmation (PIN, touch, biometrics). Any local program can also list and delete Windows Hello credentials.
- **Windows Hello** is protected the same way as your Windows account (PIN, TPM).
- **A passkey on a phone is synced** via the provider account (Google, Apple, etc.): its security equals the security of that account. The credential name contains the full database path — it is synced too.
- **Attestation is not verified:** any authenticator with PRF support is accepted.

## Troubleshooting

**"Windows WebAuthn API is not available"** — requires Windows 10 22H2 or Windows 11 (WebAuthn API v4+) and the file `C:\Windows\System32\webauthn.dll`.

**"The authenticator does not support hmac-secret/PRF" on creation**
- an old U2F key without hmac-secret — a FIDO2 key is required (YubiKey 5 and newer);
- Windows Hello without KB5077181 — update Windows 11 to build ≥ 26100.7840 / 26200.7840;
- a phone password manager without PRF (Samsung Pass, etc.) — use one with PRF support (e.g. Google Password Manager).

**"The database header has no FIDO2 device records"** — the database was not saved after the key was created, or its header is corrupted. Open a backup.

**"The authenticator presented a credential not registered in this database"** — a device removed from the database or created for another database was chosen.

**The plugin is not in the key provider list** — disable `Tools → Options → Security → Enter master key on secure desktop`: WebAuthn dialogs can't be shown there.

**The "Windows Security" window does not appear** — check whether it is hidden behind other windows; for a phone the computer needs Bluetooth.

You can check an authenticator in `Tools → KeePassPasskeyKeyProvider → PRF diagnostics`: it shows whether it enabled PRF (`bPrfEnabled`), returned a secret (`pHmacSecret`) and whether the secret matches on repeat.

## Building

```powershell
git clone https://github.com/brlumen/KeePassPasskeyKeyProvider.git
cd KeePassPasskeyKeyProvider
nuget restore KeePassPasskeyKeyProvider.sln
dotnet build KeePassPasskeyKeyProvider.csproj -c Release   # → bin\Release\KeePassPasskeyKeyProvider.dll
```

- .NET Framework 4.7.2, Visual Studio 2019+ or the `dotnet` SDK.
- KeePass must be installed: `KeePass.exe` is referenced from `C:\Program Files\KeePass Password Safe 2\`.
- The Debug configuration builds the DLL directly into KeePass's `Plugins\KeePassPasskeyKeyProvider\` (write access to that folder is required).

## Code structure

```
src/
├── KeePassPasskeyKeyProviderExt.cs        — plugin entry point: provider, menu, FIDO2 tab, KeePass events
├── FIDO2KeyProvider.cs         — Key Provider: key creation, opening, rotation
├── DeviceKeyStore.cs           — device and phrase records in the KDBX header
├── RecoveryPhrase.cs           — BIP39 recovery phrase
├── HelloCredentialAudit.cs     — search for unused Windows Hello credentials
├── FIDO2DevicesControl.cs      — "FIDO2" tab in the database settings
├── FIDO2OptionsForm.cs         — "Tools → KeePassPasskeyKeyProvider" window
├── FIDO2DiagnosticsForm.cs     — PRF diagnostics
├── DeviceNameForm.cs, RecoveryPhrase*Form.cs, BusyIndicator.cs — dialogs
└── WebAuthn/
    ├── WebAuthnApi.cs          — P/Invoke and webauthn.dll structures
    └── WebAuthnHelper.cs       — MakeCredential / GetAssertion with PRF, Windows Hello credentials
```

API documentation: [Windows WebAuthn](https://learn.microsoft.com/windows/win32/api/webauthn/), header [webauthn.h](https://github.com/microsoft/webauthn/blob/master/webauthn.h), [hmac-secret specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension), [KeePass plugins](https://keepass.info/help/v2_dev/plg_index.html).
