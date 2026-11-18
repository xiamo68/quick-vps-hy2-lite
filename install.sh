#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C.UTF-8
umask 077

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
usage() {
  printf '%s\n' 'Usage: sudo bash install.sh [--config PATH]' \
    '      sudo bash install.sh bind-domain --config PATH' \
    '      sudo bash install.sh backup OUTPUT.tar.gz' \
    '      sudo bash install.sh restore INPUT.tar.gz'
}
config=
case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  bind-domain|backup|restore)
    PYTHONPATH="$source_dir" exec /opt/hy2-lite/current/.venv/bin/python -B "$source_dir/deploy/operate_install.py" "$@" ;;
  --config) if [[ $# != 2 ]]; then usage >&2; exit 2; fi; config=$2 ;;
  '') ;;
  *) usage >&2; exit 2 ;;
esac
if (( EUID != 0 )); then
  echo 'Run the installer with sudo bash install.sh.' >&2
  exit 1
fi
if [[ ! -t 0 ]]; then
  echo 'Use an interactive SSH terminal to confirm installation and set the admin password.' >&2
  exit 1
fi

step='Read configuration'
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
trap 'printf "Installation stopped at: %s. Fix the error and retry with the same settings.\n" "$step" >&2' ERR
if [[ -z "$config" && -f install.env ]]; then config=install.env; fi
if [[ -n "$config" ]]; then
  install -m 0600 -- "$config" "$temporary/install.env"
  settings=$(python3 -B "$source_dir/deploy/install_config.py" settings "$temporary/install.env")
else
  settings=$(python3 -B "$source_dir/deploy/install_config.py" settings)
fi
read -r address port <<< "$settings"
printf 'PUBLIC_IPV4=%s\nPROXY_PORT=%s\n' "$address" "$port" > "$temporary/install.env"
base=/opt/hy2-lite
app=$base/current
etc=/etc/hy2-lite
data=/var/lib/hy2-lite
state=/var/lib/hy2-lite-install
units=/etc/systemd/system
db=$data/panel.sqlite3
acme=/var/lib/hy2-lite-acme
webroot=$acme/webroot
domain_url=https://$address
print_login() {
  printf '\n=== HY2 Lite dashboard login ===\nURL:      %s\nUsername: admin\nPassword: Use the password you entered during setup (input was hidden).\n\n' "$domain_url"
}

step='Check installation state'
exec 9>/run/lock/hy2-lite-install.lock
flock -n 9
if [[ -L "$state" || ( -e "$state" && ! -d "$state" ) ]]; then
  echo 'The installation state path is already in use.' >&2
  exit 1
fi
if [[ -d "$state" ]]; then
  if [[ $(stat -c '%u:%a' "$state") != '0:700' || -L "$state/settings" ||
        ! -f "$state/settings" || $(<"$state/settings") != "$settings" ]]; then
    echo 'Existing installation state does not match. Check the current deployment.' >&2
    exit 1
  fi
  if [[ -f "$state/complete" ]]; then
    echo 'HY2 Lite is already installed.'
    print_login
    exit 0
  fi
  echo 'Resuming the previous installation.'
else
  bash "$source_dir/check.sh" --config "$temporary/install.env"
  for name in sing-box caddy hy2-lite hy2-lite-tls; do
    if getent passwd "$name" >/dev/null || getent group "$name" >/dev/null; then
      echo "System account or group already exists: $name. Use a fresh VPS." >&2
      exit 1
    fi
  done
  for unit in sing-box caddy hy2-lite-web hy2-lite-edge hy2-lite-collector hy2-lite-executor hy2-lite-renew; do
    if [[ $(systemctl show -p LoadState --value "$unit.service") != not-found ||
          -e "$units/$unit.service" || -L "$units/$unit.service" || -d "$units/$unit.service.d" ]]; then
      echo "Service or override already exists: $unit.service. Use a fresh VPS." >&2
      exit 1
    fi
  done
  printf 'Requesting a public certificate for %s. Confirm the IP matches your cloud console and TCP 80/443 and UDP %s are open.\n' "$address" "$port"
  printf "Type INSTALL to accept the Let's Encrypt Terms of Service and continue: "
  read -r confirmation
  [[ "$confirmation" == INSTALL ]] || exit 0
  initial=$(mktemp -d /var/lib/.hy2-lite-install.XXXXXXXX)
  printf '%s\n' "$settings" > "$initial/settings"
  mv -T -- "$initial" "$state"
fi

step='Install system dependencies'
if [[ ! -f "$state/packages" ]]; then
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl caddy python3-venv iproute2
  systemctl disable --now caddy.service
  touch "$state/packages"
fi

step='Create service accounts and application directories'
getent group hy2-lite-tls >/dev/null || groupadd --system hy2-lite-tls
getent passwd hy2-lite >/dev/null ||
  useradd --system --user-group --home-dir "$data" --shell /usr/sbin/nologin hy2-lite
getent passwd sing-box >/dev/null ||
  useradd --system --user-group --home-dir /var/lib/hy2-lite-sing-box --shell /usr/sbin/nologin sing-box
install -d -m 0755 "$base" "$app" "$base/bin"
install -d -m 0751 -g hy2-lite "$etc"
install -d -m 0755 /etc/sing-box
install -d -m 0700 /var/lib/hy2-lite-operator
install -d -m 0700 -o hy2-lite -g hy2-lite "$data" "$data/backups"
install -d -m 0750 -g hy2-lite-tls "$etc/tls"
install -d -m 0755 "$acme" "$webroot"
install -d -m 0755 "$webroot/.well-known" "$webroot/.well-known/acme-challenge"

step='Install sing-box and Python dependencies'
source "$source_dir/deploy/dependencies.env"
archive=sing-box-$SING_BOX_VERSION-linux-amd64
if [[ ! -x "$base/bin/sing-box" ]]; then
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 180 --retry 2 -o "$temporary/sing-box.tar.gz" \
    "https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX_VERSION/$archive.tar.gz"
  printf '%s  %s\n' "$SING_BOX_SHA256" "$temporary/sing-box.tar.gz" | sha256sum -c -
  tar --no-same-owner -xzf "$temporary/sing-box.tar.gz" -C "$temporary" "$archive/sing-box"
  install -m 0755 "$temporary/$archive/sing-box" "$base/bin/sing-box"
fi
if [[ ! -f "$state/python" ]]; then
  cp -R --no-preserve=mode,ownership "$source_dir/hy2_lite" "$app/"
  chmod -R a+rX "$app/hy2_lite"
  (
    umask 022
    python3 -m venv "$app/.venv"
    "$app/.venv/bin/pip" --disable-pip-version-check install --timeout 15 -r "$source_dir/requirements.txt"
  )
  python3 -m venv "$base/acme-venv"
  "$base/acme-venv/bin/pip" --disable-pip-version-check install --timeout 15 "certbot==$CERTBOT_VERSION"
  ln -sfn "$base/acme-venv/bin/certbot" "$base/bin/certbot"
  touch "$state/python"
fi
# Also repair a venv created under the old umask before a resumed install.
chmod -R a+rX,go-w "$app/.venv"

step='Initialize configuration and administrator'
python3 -B "$source_dir/deploy/install_config.py" render "$temporary/install.env"
if [[ ! -f "$etc/aliases.json" ]]; then
  printf '{}\n' > "$temporary/aliases.json"
  install -m 0640 -g hy2-lite "$temporary/aliases.json" "$etc/aliases.json"
fi
cd "$app"
python=$app/.venv/bin/python
for purpose in totp subscriptions; do
  key=$etc/$purpose.fernet-key
  if [[ ! -f "$key" ]]; then
    "$python" -B -m hy2_lite --db "$db" generate-totp-key "$key"
  fi
  chgrp hy2-lite "$key"
  chmod 0640 "$key"
done
runuser -u hy2-lite -- "$python" -B -m hy2_lite --db "$db" migrate
initialized=$(runuser -u hy2-lite -- "$python" -B -c \
  'import sqlite3,sys; print(int(sqlite3.connect(sys.argv[1]).execute("SELECT EXISTS(SELECT 1 FROM admin)").fetchone()[0]))' "$db")
if [[ "$initialized" == 0 ]]; then
  printf 'Set a password for admin (at least 8 characters).\n'
  runuser -u hy2-lite -- "$python" -B -m hy2_lite --db "$db" init-admin admin
fi

step='Deploy services and issue certificate'
for unit in "$source_dir"/deploy/templates/*.service "$source_dir"/deploy/templates/*.timer \
  "$source_dir/deploy/hy2-lite-web.service" "$source_dir/deploy/hy2-lite-executor.service"; do
  install -m 0644 "$unit" "$units/"
done
install -d -m 0755 "$units/hy2-lite-web.service.d"
{
  printf '[Service]\nExecStart=\n'
  sed -n '/^ExecStart=/{s|$| --immediate-jobs --aliases-file /etc/hy2-lite/aliases.json|;p;}' "$units/hy2-lite-web.service"
} > "$temporary/web.conf"
install -m 0644 "$temporary/web.conf" "$units/hy2-lite-web.service.d/90-immediate-jobs.conf"
install -m 0755 "$source_dir/deploy/templates/publish-certificate" "$base/bin/"
systemctl daemon-reload
if [[ ! -f "$etc/edge.Caddyfile" ]]; then
  install -m 0644 "$source_dir/deploy/templates/edge-http.Caddyfile" "$etc/edge.Caddyfile"
fi
systemctl enable --now hy2-lite-edge.service
if [[ ! -s "$etc/acme/live/hy2-lite-ip/fullchain.pem" ]]; then
  "$base/bin/certbot" certonly --non-interactive --agree-tos --register-unsafely-without-email \
    --config-dir "$etc/acme" --work-dir "$acme/work" --logs-dir "$acme/logs" \
    --preferred-profile shortlived --webroot --webroot-path "$webroot" \
    --cert-name hy2-lite-ip --ip-address "$address"
fi
"$base/bin/publish-certificate"

step='Start and check services'
sed "s/@PUBLIC_IPV4@/$address/g" "$source_dir/deploy/templates/edge-https.Caddyfile" > "$temporary/edge.Caddyfile"
/usr/bin/caddy validate --config "$temporary/edge.Caddyfile" --adapter caddyfile
install -m 0644 "$temporary/edge.Caddyfile" "$etc/edge.Caddyfile"
systemctl reload hy2-lite-edge.service
"$base/bin/sing-box" -c /etc/sing-box/config.json check
systemctl enable --now sing-box.service hy2-lite-web.service
curl --fail --silent --show-error --noproxy '*' --retry 5 --retry-all-errors --retry-delay 1 \
  --max-time 5 --connect-to "$address:443:127.0.0.1:443" "$domain_url/healthz"
PYTHONPATH="$app" "$python" -B "$source_dir/deploy/check_install_probe.py"
systemctl enable --now hy2-lite-collector.service hy2-lite-executor.service hy2-lite-renew.timer
for unit in sing-box hy2-lite-web hy2-lite-edge hy2-lite-executor hy2-lite-collector; do
  systemctl is-active --quiet "$unit.service"
done
systemctl is-active --quiet hy2-lite-renew.timer
touch "$state/complete"
printf '\nInstallation complete.\n'
print_login
