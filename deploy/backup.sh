#!/usr/bin/env bash
# Backs up, or restores, the state a Spawnbox server needs to start again
# with every tenant, key, template, sandbox record and secret it had:
#
#   the database   SQLite (spawnbox.db, copied with sqlite3 VACUUM INTO) or
#                  Postgres (pg_dump of the --database-url database)
#   secrets.key    the key that seals secrets, sandbox env and CA keys
#   key files      session.key, the egress CA and the fleet CA
#
# Each backup is one tar archive encrypted with gpg (AES-256) under a
# passphrase, so the database dump and secrets.key are never stored in
# plain. Keep a copy of the passphrase away from the backups: without it
# the backups cannot be read.
#
#   backup.sh                         make a backup and drop old ones
#   backup.sh --restore FILE|URL|latest [--force] [--ignore-lease]
#                                     restore one. Every server that uses the
#                                     data must be stopped: with Postgres,
#                                     every primary sharing the database,
#                                     standbys too. --force replaces existing
#                                     data, keeping old files as *.pre-restore
#                                     and dropping the Postgres schema first.
#                                     --ignore-lease restores even while the
#                                     Postgres leader lease is held
#   backup.sh --list                  list backups at the target
#
# Settings, read from /etc/spawnbox/backup.env (SPAWNBOX_BACKUP_CONFIG)
# when it exists, or the environment:
#   SPAWNBOX_BACKUP_TARGET           a directory, or s3://bucket/prefix (needs
#                                    the aws CLI); default /var/backups/spawnbox
#   SPAWNBOX_BACKUP_KEEP             backups to keep at the target; default 14
#   SPAWNBOX_BACKUP_PASSPHRASE_FILE  default /etc/spawnbox/backup.passphrase
#   SPAWNBOX_BACKUP_METRICS_FILE     if set, a node exporter textfile to write
#                                    spawnbox_backup_last_success_timestamp_seconds to
# The server's flags come from SPAWNBOX_ARGS in /etc/spawnbox/spawnbox.env
# (SPAWNBOX_ENV_FILE): --data-dir, --database-url, --database-ca-file and
# --secrets-key-file. SPAWNBOX_DATA_DIR and SPAWNBOX_DATABASE_URL override
# them. SPAWNBOX_API_BIN is the spawn-api binary used to check a restore.
#
# Not backed up: template builds (made again from their specs on demand),
# paused sandboxes' memory and disk files (persistent sandboxes start cold
# instead), and volumes (snapshot their disk instead).
set -euo pipefail
umask 077

die() { printf 'backup: error: %s\n' "$*" >&2; exit 1; }
say() { printf 'backup: %s\n' "$*" >&2; }

config_file="${SPAWNBOX_BACKUP_CONFIG:-/etc/spawnbox/backup.env}"
if [[ -f "$config_file" ]]; then
  # shellcheck source=/dev/null
  source "$config_file"
fi
env_file="${SPAWNBOX_ENV_FILE:-/etc/spawnbox/spawnbox.env}"
SPAWNBOX_ARGS="${SPAWNBOX_ARGS:-}"
if [[ -f "$env_file" ]]; then
  # shellcheck source=/dev/null
  source "$env_file"
fi

target="${SPAWNBOX_BACKUP_TARGET:-/var/backups/spawnbox}"
keep="${SPAWNBOX_BACKUP_KEEP:-14}"
passphrase="${SPAWNBOX_BACKUP_PASSPHRASE_FILE:-/etc/spawnbox/backup.passphrase}"
api_bin="${SPAWNBOX_API_BIN:-/opt/spawnbox/bin/spawn-api}"
[[ "$keep" =~ ^[1-9][0-9]*$ ]] || die "SPAWNBOX_BACKUP_KEEP must be a positive number"

# The value of server flag $1 in SPAWNBOX_ARGS, if set.
flag() {
  local words i
  read -ra words <<<"$SPAWNBOX_ARGS"
  for ((i = 0; i < ${#words[@]}; i++)); do
    case "${words[i]}" in
      "$1") echo "${words[i + 1]:-}"; return ;;
      "$1"=*) echo "${words[i]#*=}"; return ;;
    esac
  done
}

data="${SPAWNBOX_DATA_DIR:-$(flag --data-dir)}"
data="${data:-/var/lib/spawnbox}"
database_url="${SPAWNBOX_DATABASE_URL:-$(flag --database-url)}"
database_ca="$(flag --database-ca-file)"
key_file="$(flag --secrets-key-file)"
key_file="${key_file:-$data/secrets.key}"
# Files under the data directory, besides the database, that a restore needs.
files=(session.key egress-ca.crt egress-ca.key fleet/ca.crt fleet/ca.key)

if [[ -n "$database_url" ]]; then
  mode=postgres
  if [[ -n "$database_ca" ]]; then
    export PGSSLROOTCERT="$database_ca"
    export PGSSLMODE="${PGSSLMODE:-verify-full}"
  fi
else
  mode=sqlite
fi

gpg_run() {
  gpg --homedir "$work/gnupg" --batch --quiet --pinentry-mode loopback \
    --passphrase-file "$passphrase" "$@"
}

need() {
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null || die "needs $tool; install it (apt-get install ${tool/pg_*/postgresql-client})"
  done
}

start_work() {
  [[ -d "$data" ]] || die "no data directory $data"
  [[ -r "$passphrase" ]] || die "no passphrase file $passphrase; create one, such as with: head -c 32 /dev/urandom | base64 > $passphrase"
  need gpg tar flock
  exec 9>"$data/.backup.lock"
  flock -n 9 || die "another backup or restore is running"
  work="$data/.backup"
  rm -rf "$work"
  mkdir -m 700 "$work" "$work/gnupg"
  trap 'rm -rf "$work"' EXIT
}

is_s3() { [[ "$1" == s3://* ]]; }

# Backup names, oldest first.
list() {
  if is_s3 "$target"; then
    need aws
    aws s3 ls "${target%/}/" | awk '{print $4}' | grep -E '^spawnbox-[0-9TZ]+\.tar\.gpg$' | sort || true
  else
    find "$target" -maxdepth 1 -name 'spawnbox-*.tar.gpg' -printf '%f\n' 2>/dev/null | sort || true
  fi
}

backup() {
  start_work
  local stage="$work/stage" name archive file
  mkdir -m 700 "$stage" "$stage/data"
  [[ -f "$key_file" ]] || die "no secrets key at $key_file"
  if [[ "$mode" == postgres ]]; then
    need pg_dump
    pg_dump --format=custom --no-owner --no-privileges --dbname="$database_url" \
      --file="$stage/database.dump" || die "pg_dump failed"
  else
    need sqlite3
    [[ -f "$data/spawnbox.db" ]] || die "no database at $data/spawnbox.db"
    # VACUUM INTO copies one read snapshot, so writes by the running server
    # do not make it start again, as .backup does.
    sqlite3 -cmd '.timeout 60000' "$data/spawnbox.db" \
      "VACUUM INTO '${stage//\'/\'\'}/spawnbox.db'" || die "sqlite3 VACUUM INTO failed"
  fi
  cp "$key_file" "$stage/secrets.key"
  for file in "${files[@]}"; do
    if [[ -f "$data/$file" ]]; then
      mkdir -p "$stage/data/$(dirname "$file")"
      cp "$data/$file" "$stage/data/$file"
    fi
  done
  {
    echo "format=1"
    echo "mode=$mode"
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [[ -x "$api_bin" ]]; then
      echo "version=$("$api_bin" --version 2>/dev/null || true)"
    fi
  } >"$stage/manifest"

  name="spawnbox-$(date -u +%Y%m%dT%H%M%SZ).tar.gpg"
  archive="$work/$name"
  tar -C "$stage" -cf - . | gpg_run --symmetric --cipher-algo AES256 --output "$archive"
  rm -rf "$stage"
  if is_s3 "$target"; then
    need aws
    aws s3 cp --only-show-errors "$archive" "${target%/}/$name"
  else
    mkdir -p "$target"
    cp "$archive" "$target/.$name.partial"
    mv "$target/.$name.partial" "$target/$name"
  fi
  say "wrote ${target%/}/$name ($(stat -c %s "$archive") bytes)"

  local old
  list | head -n -"$keep" | while read -r old; do
    if is_s3 "$target"; then
      aws s3 rm --only-show-errors "${target%/}/$old"
    else
      rm -f "$target/$old"
    fi
    say "removed old backup $old"
  done

  if [[ -n "${SPAWNBOX_BACKUP_METRICS_FILE:-}" ]]; then
    printf '# HELP spawnbox_backup_last_success_timestamp_seconds When the last Spawnbox backup was written.\n# TYPE spawnbox_backup_last_success_timestamp_seconds gauge\nspawnbox_backup_last_success_timestamp_seconds %s\n' \
      "$(date +%s)" >"$SPAWNBOX_BACKUP_METRICS_FILE.$$"
    chmod 644 "$SPAWNBOX_BACKUP_METRICS_FILE.$$"
    mv "$SPAWNBOX_BACKUP_METRICS_FILE.$$" "$SPAWNBOX_BACKUP_METRICS_FILE"
  fi
}

# Whether the database to restore into holds any table.
postgres_has_tables() {
  local n
  n="$(psql --dbname="$database_url" -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema()")" ||
    die "cannot connect to the database"
  [[ "$n" != 0 ]]
}

# Fails while a primary holds the Postgres leader lease, unless told to
# ignore it. A standby that is still running takes the lease within a
# second of it expiring, so a lease that stays expired means none run.
check_lease() {
  local ignore="$1" has lease
  has="$(psql --dbname="$database_url" -tAc "SELECT to_regclass('leader') IS NOT NULL")" ||
    die "cannot connect to the database"
  [[ "$has" == t ]] || return 0
  lease="$(psql --dbname="$database_url" -tAc \
    "SELECT holder || ' until ' || expires_at FROM leader WHERE id = 1 AND expires_at > now()")" ||
    die "cannot read the leader lease"
  [[ -n "$lease" ]] || return 0
  if [[ "$ignore" == yes ]]; then
    say "warning: the leader lease is held by $lease; restoring anyway (--ignore-lease)"
    return 0
  fi
  die "the leader lease is held by $lease, so a primary still uses this database. Stop spawnbox on every primary that shares it, standbys too, wait for the lease to expire (15 seconds) and run this again. --ignore-lease skips this check."
}

restore() {
  local source="$1" force="$2" ignore_lease="$3" archive file have_mode out
  if command -v systemctl >/dev/null && systemctl is-active --quiet spawnbox 2>/dev/null; then
    die "spawnbox is running; stop it first: systemctl stop spawnbox"
  fi
  start_work
  if [[ "$source" == latest ]]; then
    source="$(list | tail -n 1)"
    [[ -n "$source" ]] || die "no backups at $target"
    source="${target%/}/$source"
  fi
  archive="$work/archive.tar.gpg"
  if is_s3 "$source"; then
    need aws
    aws s3 cp --only-show-errors "$source" "$archive"
  else
    [[ -f "$source" ]] || die "no backup at $source"
    cp "$source" "$archive"
  fi
  mkdir -m 700 "$work/restore"
  gpg_run --decrypt "$archive" | tar -C "$work/restore" -xf - ||
    die "cannot decrypt $source; is $passphrase the passphrase it was made with?"
  local r="$work/restore"
  [[ -f "$r/manifest" && -f "$r/secrets.key" ]] || die "$source is not a Spawnbox backup"
  grep -qx 'format=1' "$r/manifest" || die "$source has an unknown format"
  have_mode="$(sed -n 's/^mode=//p' "$r/manifest")"
  say "restoring $(basename "$source"): $(tr '\n' ' ' <"$r/manifest")"
  [[ "$have_mode" == "$mode" ]] ||
    die "the backup is of a $have_mode database, but this server is set up for $mode (check --database-url)"

  # Check everything before changing anything.
  local replace=()
  if [[ "$mode" == postgres ]]; then
    need pg_restore psql
    check_lease "$ignore_lease"
    if postgres_has_tables; then
      [[ "$force" == yes ]] || die "the database already has tables; restore into an empty database, or pass --force to replace them"
    fi
  elif [[ -e "$data/spawnbox.db" ]]; then
    [[ "$force" == yes ]] || die "$data/spawnbox.db exists; pass --force to replace it"
    replace+=("$data/spawnbox.db" "$data/spawnbox.db-wal" "$data/spawnbox.db-shm")
  fi
  local installs=("$r/secrets.key:$key_file")
  while IFS= read -r file; do
    installs+=("$r/data/$file:$data/$file")
  done < <(cd "$r/data" && find . -type f | sed 's|^\./||' | sort)
  local pair from to
  for pair in "${installs[@]}"; do
    from="${pair%%:*}" to="${pair#*:}"
    if [[ -e "$to" ]] && ! cmp -s "$from" "$to"; then
      [[ "$force" == yes ]] || die "$to differs from the backup; pass --force to replace it"
      replace+=("$to")
    fi
  done

  for file in "${replace[@]}"; do
    if [[ -e "$file" ]]; then
      mv "$file" "$file.pre-restore"
      say "kept the old $file as $file.pre-restore"
    fi
  done
  if [[ "$mode" == postgres ]]; then
    # The SQL is written out in full first, so a failed pg_restore cannot
    # leave psql to commit half of it. With --force, the schema is dropped
    # and made again in the same transaction, so tables that a later
    # version added do not survive next to an older schema_version.
    local schema sql="$work/restore.sql"
    : >"$sql"
    if [[ "$force" == yes ]]; then
      schema="$(psql --dbname="$database_url" -tAc "SELECT quote_ident(current_schema())")" ||
        die "cannot connect to the database"
      [[ -n "$schema" ]] || die "the database has no current schema"
      printf 'DROP SCHEMA %s CASCADE;\nCREATE SCHEMA %s;\n' "$schema" "$schema" >"$sql"
    fi
    # The schema itself is made above, or already exists.
    pg_restore -l "$r/database.dump" >"$work/restore.list" || die "cannot read the database dump"
    sed -i '/ SCHEMA - /d' "$work/restore.list"
    pg_restore --no-owner --no-privileges --exit-on-error -L "$work/restore.list" \
      -f - "$r/database.dump" >>"$sql" || die "pg_restore failed"
    psql --dbname="$database_url" --single-transaction -v ON_ERROR_STOP=1 -q -f "$sql" >/dev/null ||
      die "the restore failed and was rolled back; the database is as it was"
  else
    install -m 600 "$r/spawnbox.db" "$data/spawnbox.db"
  fi
  for pair in "${installs[@]}"; do
    from="${pair%%:*}" to="${pair#*:}"
    mkdir -p "$(dirname "$to")"
    install -m 600 "$from" "$to"
  done
  # Fleet identities signed by an old CA are made again from the restored one.
  if [[ "${#replace[@]}" -gt 0 && -d "$data/fleet/primary" ]]; then
    rm -rf "$data/fleet/primary"
  fi
  say "restored into $data${database_url:+ and the Postgres database}"

  if [[ -x "$api_bin" ]]; then
    out=(--data-dir "$data" --secrets-key-file "$key_file")
    [[ -n "$database_ca" ]] && out+=(--database-ca-file "$database_ca")
    env ${database_url:+SPAWNBOX_DATABASE_URL="$database_url"} "$api_bin" check-data "${out[@]}" ||
      die "the restored data does not check out"
  else
    say "no $api_bin; run spawn-api check-data before starting the server"
  fi
}

case "${1:-}" in
  "") backup ;;
  --list) list ;;
  --restore)
    [[ -n "${2:-}" ]] || die "--restore needs a backup file, s3:// URL or latest"
    from="$2" force=no ignore_lease=no
    shift 2
    for arg in "$@"; do
      case "$arg" in
        --force) force=yes ;;
        --ignore-lease) ignore_lease=yes ;;
        *) die "unknown option $arg" ;;
      esac
    done
    restore "$from" "$force" "$ignore_lease"
    ;;
  -h | --help) sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown option $1 (see --help)" ;;
esac
