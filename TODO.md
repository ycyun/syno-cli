# TODO List

## 1. Shared Folder Encryption & Management (`share`)
Referenced from `synology-cli.sh`:
- [ ] **List Shares (`share list` / `share ls`)**:
  - API: `SYNO.Core.Share` (version 1, method `list`)
  - Additional attributes: `["hidden", "encryption"]`
  - Display shares and encryption status (plain, encrypted/locked `encryption=1`, decrypted/unlocked `encryption=2`).
- [ ] **Unlock Shared Folder (`share unlock` / `share decrypt`)**:
  - API: `SYNO.Core.Share.Crypto` (version 1, method `decrypt`)
  - Parameters: `name`, `password`
  - Interactive password prompt or CLI option.
- [ ] **Lock Shared Folder (`share lock` / `share encrypt`)**:
  - API: `SYNO.Core.Share.Crypto` (version 1, method `encrypt`)
  - Parameters: `name`
  - Lock decrypted shared folder back into encrypted state.

## 2. Session Management & 2FA Enhancements
- [x] **2FA Support for DSM 7.2.2+**:
  - Automatic 2FA challenge detection (code 403, 406, `error.errors.token`).
  - Interactive terminal prompt (`🔐 2FA detected. Please enter OTP:`).
  - CLI flags: `--synology.otp`, `--synology.otp-secret`.
  - Environment variables: `SYNOLOGY_OTP`, `SYNOLOGY_OTP_SECRET` (with `NAS_*` fallbacks).
  - Automatic TOTP code generation from Base32 secret using `github.com/pquerna/otp/totp`.
  - Session ID (`SID`) tracking and `Logout` method.
- [ ] **Device Token (Trusted Device)**:
  - Add optional `device_token` support to remember trusted device across CLI invocations without re-prompting OTP.
