# Building and Releasing SecureUSB

This document explains how to produce downloadable executables for Windows and macOS using PyInstaller and GitHub Actions.

Prerequisites
- Python 3.10+ installed
- pip available
- On macOS: Xcode command line tools may be required for building

Local builds

macOS / Linux (bash):

```bash
./scripts/build_release.sh
```

This will create a one-file executable `dist/SecureUSB` and copy it to your Desktop if it exists.

Windows (PowerShell):

```powershell
.\scripts\build_release_windows.ps1
```

This will create `dist\SecureUSB.exe` and copy it to your Desktop.

CI (GitHub Actions)

A workflow is included at `.github/workflows/build-release.yml`. It triggers on tag pushes (tags starting with `v`) and on manual dispatch.

Per-OS build jobs (macOS and Windows) install dependencies, run PyInstaller, create a basic installer artifact (`.dmg` for macOS, NSIS installer for Windows), and upload artifacts for that runner.

When you push a tag (for example `v1.0.0`) an additional `create_release` job runs. It downloads the artifacts from the build jobs and attaches them to a GitHub Release created for that tag. The workflow uses the provided `GITHUB_TOKEN` so no additional token is required for basic releases.

Notes and next steps

- Code signing: macOS and Windows users expect signed binaries. You should sign the Windows `.exe` with an Authenticode certificate and macOS apps with an Apple Developer ID and perform notarization. These steps are not automated here.

- Code signing / notarization: The workflow contains placeholder steps which only run when signing secrets are present. To enable signing in CI you should add the following secrets to the repository:
	- `WINDOWS_CERT_PFX` (PFX file as a base64 string or upload strategy) and `WINDOWS_CERT_PASSWORD` — used by signtool.
	- `MAC_SIGNING_ID` and appropriate notarization credentials — used by `codesign` and `notarytool`/`altool`.

	Implementing CI signing requires securely storing certificates in GitHub Secrets or a secret manager and writing concrete signing commands that import the certificates inside the runner.

- Installers: For a proper install experience you can create an NSIS or Inno Setup installer for Windows and a `.dmg` or signed `.pkg` for macOS. This is recommended for UX and to place an app on the Applications folder.

Installer features implemented

- Desktop shortcut: The NSIS installer creates a Desktop shortcut; the macOS `.app` when installed by user will be placed by them (the DMG provides the app bundle).
- Start Menu entry: The NSIS script creates a Start Menu shortcut under the program's folder.
- Uninstall: The NSIS installer writes an uninstaller (`Uninstall.exe`) and registers an uninstall entry in the Windows registry so the app appears in "Add/Remove Programs".
- Install dir default: The NSIS installer defaults to `%ProgramFiles%\SecureUSB` but allows the user to choose a directory during install.

Windows (NSIS)

The `installer/secureusb.nsi` file contains a compact NSIS script that:

- Bundles `SecureUSB.exe` inside the installer
- Creates Desktop and Start Menu shortcuts
- Writes an uninstaller and the uninstall registry entry
- Defaults install location to `%ProgramFiles%\\SecureUSB`

macOS (.app + DMG)

The `scripts/package_mac_app.sh` script wraps the `dist/SecureUSB` binary into a minimal `.app` bundle and then creates a `SecureUSB.dmg`. A typical user will drag the `.app` into `/Applications` from the DMG. For production you should sign the `.app` and notarize the DMG.

- Portable vs packaged app: PyInstaller bundles a Python interpreter and dependencies into a single file. The resulting executables may be large.

- Compatibility: Build on each target OS for reliable binaries (Windows builds on windows-latest runner, macOS on macos-latest). Cross-building is not supported by PyInstaller.

Troubleshooting

If the executable fails to run, run `dist/SecureUSB --help` or open a terminal to see stdout/stderr. Check that required OS-level dependencies are installed.

Security

Avoid bundling secrets. For releases, review `requirements.txt` for known CVEs and run tests before tagging a release.
