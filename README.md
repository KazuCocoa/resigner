# resigner

Resigner is a Go library for re-signing iOS .ipa files, mainly for Appium/WebDriverAgentRunner workflows.

Please do not use this for production app signing.

## Requirements

- macOS (Not tested on other platforms, but might work with Go's cross-compilation)
- go 1.26.1 or later
- Xcode command line tools (for `codesign` and `security`)

## Download Pre-built Binaries
- [Releases](https://github.com/KazuCocoa/resigner/releases)

### Get via CLI

#### macOS (Intel)
```bash
curl -LO https://github.com/KazuCocoa/resigner/releases/download/<version>/darwin-amd64.tar.gz
```

#### macOS (Apple Silicon)
```bash
curl -LO https://github.com/KazuCocoa/resigner/releases/download/<version>/darwin-arm64.tar.gz
```

#### Linux (AMD64)
```bash
curl -LO https://github.com/KazuCocoa/resigner/releases/download/<version>/linux-amd64.tar.gz
```

#### Linux (386)
```bash
curl -LO https://github.com/KazuCocoa/resigner/releases/download/<version>/linux-386.tar.gz
```

#### Windows (386) - PowerShell
```powershell
Invoke-WebRequest -Uri "https://github.com/KazuCocoa/resigner/releases/download/<version>/windows-386.zip" -OutFile "resigner-windows-386.zip"
```

#### Windows (AMD64) - PowerShell
```powershell
Invoke-WebRequest -Uri "https://github.com/KazuCocoa/resigner/releases/download/<version>/windows-amd64.zip" -OutFile "resigner-windows-amd64.zip"
```

**Note:** Replace `<version>` with the latest version from [Releases](https://github.com/KazuCocoa/resigner/releases)

## Quick Start: Re-sign App

```bash
resigner \
  --p12-file "<path to p12 file>" \
  --p12-password "<password of p12>" \
  --profile "<path to provisioning profiles>" \
  --force \
  --bundle-id-remap "com.facebook.WebDriverAgentRunner=<valid bundle id for the profile>" \
  --bundle-id-remap "com.facebook.WebDriverAgentRunner.xctrunner=<valid bundle id for the profile>" \
  --bundle-id-remap "com.facebook.WebDriverAgentLib=<valid bundle id for the profile>" \
  /path/to/WebDriverAgentRunner-Runner.app
```

`<valid bundle id for the profile>` should match the provisioning profile app identifier.

## Inspect Current Signatures

```bash
resigner --inspect /path/to/WebDriverAgentRunner-Runner.app
resigner --inspect /path/to/WebDriverAgentRunner-Runner.ipa
```

This prints each discovered bundle path with:
- current Info.plist bundle identifier
- current signed code identifier
- team identifier
- leaf signing certificate common name

## Create PKCS#12 (.p12)

Use the `.p12` with `--p12-file`, and its password with `--p12-password`.

### Option 1: Keychain Access (recommended)

- Open Keychain Access.
- Find your Apple Development certificate with a private key.
- Export as `Personal Information Exchange (.p12)`.
- Set an export password.

### Option 2: OpenSSL (if you already have PEM files)

```bash
openssl pkcs12 -export \
  -inkey key.pem \
  -in cert.pem \
  -out mysign.p12
```

### Option 3: Free Apple Account (Xcode-managed)

- Add your Apple ID in `Xcode > Settings > Accounts`.
- Enable `Automatically manage signing` for your target and personal team.
- Build once on a real device to generate an Apple Development cert and profile.
- In Keychain Access (`login > My Certificates`), export the Apple Development certificate as `.p12`.

Tips:
- If the certificate is missing in Keychain, run another real-device build in Xcode.
- Free-account profiles are usually in `~/Library/Developer/Xcode/UserData/Provisioning Profiles`.

### CLI Export: All identities in login keychain

`security export -t identities` exports all exportable identities from the specified keychain.

```bash
# generate a strong random password
P12_PASSWORD="$(openssl rand -base64 24 | tr -d '\n')"

# export identities to p12 using that password
security export \
  -k ~/Library/Keychains/login.keychain-db \
  -t identities \
  -f pkcs12 \
  -P "$P12_PASSWORD" \
  -o ~/sign/mysign.p12

# show it once so you can store it in your secret manager
echo "$P12_PASSWORD"
```

### CLI Export: Only one specific identity

Use this if you want a `.p12` that contains exactly one identity from `security find-identity`.

```bash
# choose SHA-1 from: security find-identity -v -p codesigning ~/Library/Keychains/login.keychain-db
TARGET_SHA1="PUT_SHA1_HERE"

# passwords for temporary operations and final p12
TMP_PASS="$(openssl rand -base64 24 | tr -d '\n')"
P12_PASSWORD="$(openssl rand -base64 24 | tr -d '\n')"

# create temporary workspace
TMP_DIR="$(mktemp -d /tmp/resigner-p12.XXXXXX)"
TMP_KC="$TMP_DIR/one.keychain-db"

# export from login keychain, then import into temporary keychain
security export -k ~/Library/Keychains/login.keychain-db -t identities -f pkcs12 -P "$TMP_PASS" -o "$TMP_DIR/all.p12"
security create-keychain -p "$TMP_PASS" "$TMP_KC"
security unlock-keychain -p "$TMP_PASS" "$TMP_KC"
security import "$TMP_DIR/all.p12" -k "$TMP_KC" -P "$TMP_PASS"

# keep only TARGET_SHA1
for s in $(security find-identity -v -p codesigning "$TMP_KC" | awk '/"/ {print $2}'); do
  [ "$s" = "$TARGET_SHA1" ] || security delete-identity -Z "$s" "$TMP_KC"
done

# export the remaining identity as p12
security export -k "$TMP_KC" -t identities -f pkcs12 -P "$P12_PASSWORD" -o ~/sign/mysign-specific.p12

# show outputs once, then clean up temp files
echo "P12: ~/sign/mysign-specific.p12"
echo "PASSWORD: $P12_PASSWORD"
security delete-keychain "$TMP_KC" 2>/dev/null || true
rm -rf "$TMP_DIR"
```

### Optional Sanity Check

```bash
openssl pkcs12 -info -in mysign.p12 -noout
```

## Provisioning Profile Checks

### Profile Locations for '--profile' argument

- Xcode auto-generated (including free account): `~/Library/Developer/Xcode/UserData/Provisioning Profiles`
- System-cached profiles: `~/Library/MobileDevice/Provisioning Profiles`

Recommended to copy the target profile to a separate directory and point `--profile` there,
to avoid accidentally using an unintended profile.

### Decode a Profile

```bash
security cms -D -i /path/to/profile.mobileprovision > /tmp/profile.plist
```

### Check Expiration Date

```bash
/usr/libexec/PlistBuddy -c "Print :ExpirationDate" /tmp/profile.plist
# Output example: Sat Apr 04 22:12:21 PST 2026
```

### Check Bundle ID (App Identifier)

```bash
/usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" /tmp/profile.plist
```

### Verify Free-Account Usability

```bash
# Check development flag (should be true for free accounts)
/usr/libexec/PlistBuddy -c "Print :Entitlements:get-task-allow" /tmp/profile.plist

# Check team identifier
/usr/libexec/PlistBuddy -c "Print :TeamIdentifier:0" /tmp/profile.plist

# List provisioned device UDIDs (must include target device)
/usr/libexec/PlistBuddy -c "Print :ProvisionedDevices" /tmp/profile.plist
```

### Quick Scan Profiles

```bash
# Scan for matching profiles and show expiration status
BUNDLE_ID_SUBSTR="com.kazucocoa.WebDriverAgentRunner"
for f in /path/to/profiles/*; do
  [ -f "$f" ] || continue
  security cms -D -i "$f" > /tmp/p.plist 2>/dev/null || continue
  appid=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" /tmp/p.plist 2>/dev/null)
  if [[ "$appid" == *"$BUNDLE_ID_SUBSTR"* ]]; then
    echo "FILE:$f"
    /usr/libexec/PlistBuddy -c "Print :Name" /tmp/p.plist
    /usr/libexec/PlistBuddy -c "Print :ExpirationDate" /tmp/p.plist
    echo "---"
  fi
done
```

## Building from Source

```bash
make
```

```bash
make all
```

## Testing

```bash
go test ./...
```

## Release Process

```bash
# Update CHANGELOGS.md and commit it.
git tag <new_version>  # please add `v` prefix, e.g. `v0.1.1`
git push origin <new_version>
```
