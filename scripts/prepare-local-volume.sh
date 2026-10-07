set -eu

fail() { printf '%s\n' "$1" >&2; exit 1; }
valid_publisher() {
  case "$1" in
    ''|.*|*.|incoming|processed|hatali|published|audit|*[!A-Za-z0-9._+-]*) return 1 ;;
  esac
  test "${#1}" -le 128
}

mode=copy
if test "${1:-}" = --inventory; then mode=inventory; shift; fi
test -n "${1:-}" || fail 'Supply the mounted volume directory'
volume=$(cd "$1" && pwd -P) || fail 'Volume directory is unavailable'
if test "$mode" = inventory; then
  for source in "$volume"/*; do
    publisher=${source##*/}
    if test -d "$source" && test ! -L "$source" && valid_publisher "$publisher"; then
      if test -n "$(find "$source" -mindepth 3 -maxdepth 3 -type f -name extension.vsixmanifest -print -quit)"; then printf '%s\n' "$publisher"; fi
    fi
  done
  exit 0
fi

test "$(id -u)" = "${MARKETPLACE_UID:-1000}" || fail 'Run with the same UID as the importer; default UID is 1000'
test -w "$volume" || fail 'Volume is not writable'
test -f "${2:-}" || fail 'Supply a reviewed publisher list file'
list=$2
for directory in published incoming audit; do
  test ! -L "$volume/$directory" || fail 'Operational directories must not be symlinks'
  if test -e "$volume/$directory"; then test -d "$volume/$directory" || fail 'Operational path is not a directory'; fi
done
shift 2
set --
seen=' '
required_kib=65536
while IFS= read -r publisher || test -n "$publisher"; do
  publisher=$(printf '%s' "$publisher" | tr -d '\r')
  test -n "$publisher" || continue
  valid_publisher "$publisher" || fail 'Invalid or reserved publisher name'
  case "$seen" in *" $publisher "*) fail 'Duplicate publisher name' ;; esac
  seen="$seen$publisher "
  source="$volume/$publisher"
  test -d "$source" && test ! -L "$source" || fail 'Publisher source directory is unavailable'
  test ! -e "$volume/published/$publisher" && test ! -L "$volume/published/$publisher" || fail 'Destination exists; refusing to overwrite'
  test -z "$(find "$source" -type l -print -quit)" || fail 'Source contains symlinks; operator review is required'
  test -n "$(find "$source" -mindepth 3 -maxdepth 3 -type f -name extension.vsixmanifest -print -quit)" || fail 'Source contains no version manifests'
  size=$(du -sk "$source" | awk '{print $1}')
  required_kib=$((required_kib + size))
  set -- "$@" "$publisher"
done < "$list"
test "$#" -gt 0 || fail 'Publisher list is empty'
available_kib=$(df -Pk "$volume" | awk 'END {print $4}')
test "$available_kib" -ge "$required_kib" || fail 'Insufficient free space for a verified copy'
umask 027
mkdir -p "$volume/published" "$volume/incoming" "$volume/audit"
stage=$(mktemp -d "$volume/.migration.XXXXXX")
printf 'Staging: %s\n' "$stage"
for publisher do
  cp -a "$volume/$publisher" "$stage/$publisher"
  diff -r "$volume/$publisher" "$stage/$publisher" >/dev/null || fail 'Copy verification failed; source and staging are preserved'
done
for publisher do
  test ! -e "$volume/published/$publisher" && test ! -L "$volume/published/$publisher" || fail 'Destination changed during migration; staging is preserved'
  mv "$stage/$publisher" "$volume/published/$publisher"
  printf 'Copied: %s\n' "$publisher"
done
rmdir "$stage"
printf 'Migration complete. Original catalog directories are preserved.\n'
