set -eu

test_root=$(mktemp -d)
volume="$test_root/volume"
mkdir -p "$volume/ms-vscode/keymap/1.0.7" "$volume/incoming/untrusted/1.0.0"
printf 'manifest' > "$volume/ms-vscode/keymap/1.0.7/extension.vsixmanifest"
printf 'package-bytes' > "$volume/ms-vscode/keymap/1.0.7/package.vsix"
printf 'signature-bytes' > "$volume/ms-vscode/keymap/1.0.7/package.sigzip"
printf 'unapproved' > "$volume/incoming/untrusted/1.0.0/extension.vsixmanifest"
printf 'ms-vscode\r\n' > "$test_root/publishers.txt"
export MARKETPLACE_UID
MARKETPLACE_UID=$(id -u)
test "$(sh scripts/prepare-local-volume.sh --inventory "$volume")" = ms-vscode
sh scripts/prepare-local-volume.sh "$volume" "$test_root/publishers.txt"
diff -r "$volume/ms-vscode" "$volume/published/ms-vscode"
test ! -e "$volume/published/incoming"
test -f "$volume/incoming/untrusted/1.0.0/extension.vsixmanifest"
test -d "$volume/audit"
if sh scripts/prepare-local-volume.sh "$volume" "$test_root/publishers.txt"; then exit 1; fi
printf '../escape\n' > "$test_root/invalid.txt"
if sh scripts/prepare-local-volume.sh "$volume" "$test_root/invalid.txt"; then exit 1; fi
test -f "$volume/published/ms-vscode/keymap/1.0.7/package.vsix"
printf 'Local volume copy and rejection checks passed: %s\n' "$test_root"
