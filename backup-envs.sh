#!/bin/bash
# Collect every .env / key / keystore across all projects into ONE encrypted archive.
# Safe to store anywhere (Drive, iCloud, email) - AES-256 encrypted.
#
#   ./backup-envs.sh                 create the encrypted bundle
#   ./backup-envs.sh --list          show what WOULD be collected, write nothing
#   ./backup-envs.sh --restore FILE  unpack a bundle
#   ./backup-envs.sh --verify FILE   prove an existing bundle opens
#
# Asks for the password ONCE, then proves the archive decrypts with it before
# reporting success. No "type it twice" mismatch.
set -uo pipefail

ROOT="$HOME"
OUT="$HOME/env-backup-$(date +%Y-%m-%d).tar.gz.enc"
SKIP_RE='^(Library|Downloads|Movies|Music|Pictures|Public|Applications|flutter|go|Parallels)'
ENC_ARGS=(-aes-256-cbc -pbkdf2 -iter 200000)

USE_CLIP=false
for a in "$@"; do [ "$a" = "--clip" ] && USE_CLIP=true; done

# Grab the clipboard IMMEDIATELY at startup. The macOS Passwords app wipes the
# clipboard roughly 60s after a copy, and scanning every project takes longer
# than that - so reading it later finds nothing.
CLIP_EARLY=""
$USE_CLIP && CLIP_EARLY=$(pbpaste 2>/dev/null | tr -d '\r\n')

ask_pw() {
  if $USE_CLIP; then
    ENVBK_PW="$CLIP_EARLY"
    [ -z "$ENVBK_PW" ] && ENVBK_PW=$(pbpaste 2>/dev/null | tr -d '\r\n')
    while [ -z "$ENVBK_PW" ]; do
      echo >&2
      echo "Clipboard is empty - macOS Passwords wipes it ~60s after copying." >&2
      echo "Copy the password again NOW, then press Return here." >&2
      read -r _ < /dev/tty || { echo "Aborted." >&2; exit 1; }
      ENVBK_PW=$(pbpaste 2>/dev/null | tr -d '\r\n')
    done
    echo "Using password from clipboard: ${#ENVBK_PW} characters." >&2
    if [ "${#ENVBK_PW}" -lt 12 ]; then
      echo "That looks too short to be your generated password." >&2
      echo "Make sure you used 'Copy Password', not 'Copy Username'." >&2
      exit 1
    fi
  else
    printf '%s' "$1" >&2
    IFS= read -rs ENVBK_PW
    printf '\n' >&2
    [ -n "$ENVBK_PW" ] || { echo "Empty password - aborting." >&2; exit 1; }
  fi
  export ENVBK_PW
}

# ---------------------------------------------------------------- verify
if [ "${1:-}" = "--verify" ]; then
  src="${2:?usage: $0 --verify <file.tar.gz.enc>}"
  [ -f "$src" ] || { echo "no such file: $src"; exit 1; }
  ask_pw "Password for $(basename "$src"): "
  n=$(openssl enc -d "${ENC_ARGS[@]}" -pass env:ENVBK_PW -in "$src" 2>/dev/null \
        | tar tzf - 2>/dev/null | grep -v '/$' | grep -c . )
  unset ENVBK_PW
  if [ "${n:-0}" -gt 0 ]; then
    echo "OK - decrypts cleanly, $n file(s) inside (includes MANIFEST.txt)."
  else
    echo "FAILED - wrong password, or the archive is damaged."; exit 1
  fi
  exit 0
fi

# ------------------------------------------------------- restore in place
# Puts every file back where it came from, under $HOME. Anything already
# there that differs is saved as <file>.bak-<timestamp> first, so this can
# never silently destroy a newer secret.
if [ "${1:-}" = "--restore-inplace" ]; then
  src="${2:?usage: $0 --restore-inplace <file.tar.gz.enc> [--clip]}"
  [ -f "$src" ] || { echo "no such file: $src"; exit 1; }
  ask_pw "Password for $(basename "$src"): "
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  if ! openssl enc -d "${ENC_ARGS[@]}" -pass env:ENVBK_PW -in "$src" 2>/dev/null | tar xzf - -C "$tmp" 2>/dev/null; then
    unset ENVBK_PW; echo "Decryption failed - wrong password."; exit 1
  fi
  unset ENVBK_PW
  stamp=$(date +%Y%m%d-%H%M%S); put=0; kept=0; same=0
  while IFS= read -r rel; do
    [ "$rel" = "MANIFEST.txt" ] && continue
    srcf="$tmp/$rel"; dstf="$HOME/$rel"
    if [ -f "$dstf" ]; then
      if cmp -s "$srcf" "$dstf"; then same=$((same+1)); continue; fi
      cp -p "$dstf" "$dstf.bak-$stamp"; kept=$((kept+1))
      echo "  ~ $rel  (existing saved as .bak-$stamp)"
    else
      mkdir -p "$(dirname "$dstf")"
      echo "  + $rel"
    fi
    cp -p "$srcf" "$dstf" && put=$((put+1))
  done < <(cd "$tmp" && find . -type f | sed 's|^\./||' | sort)
  echo
  echo "Restored $put file(s) into place under $HOME."
  [ "$same" -gt 0 ] && echo "$same already identical, left alone."
  [ "$kept" -gt 0 ] && echo "$kept existing file(s) backed up as .bak-$stamp - delete those once happy."
  exit 0
fi

# ---------------------------------------------------------------- restore
if [ "${1:-}" = "--restore" ]; then
  src="${2:?usage: $0 --restore <file.tar.gz.enc>}"
  [ -f "$src" ] || { echo "no such file: $src"; exit 1; }
  dest="$HOME/env-restore-$(date +%s)"
  ask_pw "Password for $(basename "$src"): "
  mkdir -p "$dest"
  if openssl enc -d "${ENC_ARGS[@]}" -pass env:ENVBK_PW -in "$src" 2>/dev/null | tar xzf - -C "$dest" 2>/dev/null; then
    unset ENVBK_PW
    echo "Restored to: $dest"
    find "$dest" -type f | sed 's/^/  /'
    echo
    echo "Review, then copy each file back into its project folder."
  else
    unset ENVBK_PW; rm -rf "$dest"
    echo "Decryption failed - wrong password."; exit 1
  fi
  exit 0
fi

# ---------------------------------------------------------------- collect
STAGE=$(mktemp -d); VTMP=""
cleanup() { rm -rf "$STAGE" ${VTMP:+"$VTMP"}; unset ENVBK_PW 2>/dev/null || true; }
trap cleanup EXIT

count=0
cd "$ROOT" || exit 1
for d in */; do
  p="${d%/}"
  [[ "$p" =~ $SKIP_RE ]] && continue
  [ -d "$p" ] || continue
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in *.env.example|*.env.sample) continue;; esac
    mkdir -p "$STAGE/$(dirname "$f")"
    cp -p "$f" "$STAGE/$f" 2>/dev/null && count=$((count+1)) && echo "  + $f"
  done < <(find "$p" -maxdepth 4 \
             \( -name ".env" -o -name ".env.*" -o -name "*.pem" -o -name "*.p12" \
                -o -name "*serviceAccount*.json" -o -name "*.keystore" -o -name "*.jks" \) \
             -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null)
done

echo
echo "$count secret file(s) found."
[ "$count" -eq 0 ] && { echo "Nothing to back up."; exit 0; }
[ "${1:-}" = "--list" ] || [ "${2:-}" = "--list" ] && { echo "(--list: nothing written)"; exit 0; }

( cd "$STAGE" && find . -type f | sed 's|^\./||' | sort ) > "$STAGE/MANIFEST.txt"

echo
echo "Paste the password from your password manager, then press Return."
echo "Nothing appears on screen - that is normal. You are asked only ONCE;"
echo "the archive is then tested to prove it opens."
echo
ask_pw "Password: "

if ! tar czf - -C "$STAGE" . | openssl enc "${ENC_ARGS[@]}" -salt -pass env:ENVBK_PW -out "$OUT" 2>/dev/null; then
  echo "Encryption failed."; rm -f "$OUT"; unset ENVBK_PW; exit 1
fi
chmod 600 "$OUT"

# ------------------------------------------------- prove it actually opens
echo "Verifying the archive really decrypts with that password..."
VTMP=$(mktemp -d)
if ! openssl enc -d "${ENC_ARGS[@]}" -pass env:ENVBK_PW -in "$OUT" 2>/dev/null | tar xzf - -C "$VTMP" 2>/dev/null; then
  echo "VERIFY FAILED - did not decrypt. Deleting it so you never trust a broken backup."
  rm -f "$OUT"; unset ENVBK_PW; exit 1
fi
got=$(find "$VTMP" -type f ! -name MANIFEST.txt | wc -l | tr -d ' ')
unset ENVBK_PW

if [ "$got" -ne "$count" ]; then
  echo "VERIFY FAILED - expected $count files, archive holds $got. Deleting it."
  rm -f "$OUT"; exit 1
fi

echo
echo "VERIFIED: $got/$count files, decrypted successfully with your password."
echo "Written: $OUT  ($(du -h "$OUT" | cut -f1))"
echo
echo "This file is encrypted - safe for iCloud Drive, Google Drive or email."
echo "NOW COPY IT OFF THIS MAC. Later you can check it any time with:"
echo "  ./backup-envs.sh --verify $OUT"
