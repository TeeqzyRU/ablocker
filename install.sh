#!/usr/bin/env bash
#
# ablocker installer — ставит как tblocker, одной командой:
#   curl -fsSL https://raw.githubusercontent.com/TeeqzyRU/ablocker/main/install.sh -o ablocker-install.sh && bash ablocker-install.sh
#
set -euo pipefail

# >>> ЗАМЕНИ на свой репозиторий (owner/repo) <<<
GH_REPO="${GH_REPO:-TeeqzyRU/ablocker}"

INSTALL_DIR="/opt/ablocker"
BIN="$INSTALL_DIR/ablocker"
SERVICE="/etc/systemd/system/ablocker.service"
RAW="https://raw.githubusercontent.com/$GH_REPO/main"

red()   { printf "\033[31m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
blue()  { printf "\033[34m%s\033[0m\n" "$*"; }

[ "$(id -u)" -eq 0 ] || { red "Запусти от root (sudo)."; exit 1; }

# --- arch ---
case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) red "Неподдерживаемая архитектура: $(uname -m)"; exit 1 ;;
esac
blue "Архитектура: $ARCH"

# --- deps: conntrack + firewall tools ---
install_pkg() {
  if   command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y "$@" >/dev/null
  elif command -v dnf     >/dev/null; then dnf install -y "$@" >/dev/null
  elif command -v yum     >/dev/null; then yum install -y "$@" >/dev/null
  elif command -v apk     >/dev/null; then apk add --no-cache "$@" >/dev/null
  else red "Не нашёл пакетный менеджер — поставь $* вручную."; fi
}
command -v conntrack >/dev/null || { blue "Ставлю conntrack..."; install_pkg conntrack || install_pkg conntrack-tools || true; }

# --- stop old ---
systemctl stop ablocker 2>/dev/null || true

mkdir -p "$INSTALL_DIR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# --- download release binary, matching .goreleaser archive name ---
get_latest_tag() {
  curl -fsSL "https://api.github.com/repos/$GH_REPO/releases/latest" \
    | grep -m1 '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

download_release() {
  local tag="$1"
  local file="ablocker-${tag}-linux-${ARCH}.tar.gz"
  local url="https://github.com/$GH_REPO/releases/download/${tag}/${file}"
  blue "Качаю $url"
  curl -fsSL "$url" -o "$TMP/$file" || return 1
  tar -xzf "$TMP/$file" -C "$TMP" || return 1
  [ -f "$TMP/ablocker" ] || return 1
  install -m 0755 "$TMP/ablocker" "$BIN"
  [ -f "$TMP/config.yaml.default" ] && cp "$TMP/config.yaml.default" "$INSTALL_DIR/config.yaml.default"
  return 0
}

build_from_source() {
  command -v go >/dev/null || { red "Нет релиза и нет Go для сборки из исходников."; return 1; }
  blue "Релиз не найден — собираю из исходников..."
  git clone --depth 1 "https://github.com/$GH_REPO.git" "$TMP/src" >/dev/null 2>&1 || return 1
  ( cd "$TMP/src" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BIN" . ) || return 1
  cp "$TMP/src/config.yaml.default" "$INSTALL_DIR/config.yaml.default"
  return 0
}

TAG="$(get_latest_tag || true)"
if [ -n "${TAG:-}" ] && download_release "$TAG"; then
  green "Бинарь установлен из релиза $TAG"
elif build_from_source; then
  green "Бинарь собран из исходников"
else
  red "Не удалось ни скачать релиз, ни собрать. Проверь GH_REPO и наличие релизов."
  exit 1
fi

# --- config (не перезатираем существующий) ---
if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
  cp "$INSTALL_DIR/config.yaml.default" "$INSTALL_DIR/config.yaml"
  green "Создан $INSTALL_DIR/config.yaml"
else
  blue "config.yaml уже есть — оставляю как есть."
fi

# --- interactive tweaks ---
if [ -t 0 ]; then
  read -rp "Путь к access.log [$(grep -oP 'LogFile:\s*"\K[^"]+' "$INSTALL_DIR/config.yaml" || echo /var/log/remnanode/access.log)]: " LOGP || true
  if [ -n "${LOGP:-}" ]; then sed -i "s|^LogFile:.*|LogFile: \"$LOGP\"|" "$INSTALL_DIR/config.yaml"; fi

  read -rp "Firewall [iptables/nft] (iptables): " FW || true
  if [ "${FW:-}" = "nft" ]; then sed -i 's|^BlockMode:.*|BlockMode: "nft"|' "$INSTALL_DIR/config.yaml"; fi

  read -rp "Включить блокировку malware/botnet? [Y/n]: " MW || true
  if [ "${MW:-Y}" = "n" ] || [ "${MW:-Y}" = "N" ]; then
    sed -i 's|^MalwareBlockEnabled:.*|MalwareBlockEnabled: false|' "$INSTALL_DIR/config.yaml"
  fi
fi

# --- logrotate для логов ноды (чтобы лог Xray не забил диск) ---
LOG_DIR="$(dirname "$(grep -oP 'LogFile:\s*"\K[^"]+' "$INSTALL_DIR/config.yaml" 2>/dev/null || echo /var/log/remnanode/access.log)")"
command -v logrotate >/dev/null 2>&1 || install_pkg logrotate || true
if command -v logrotate >/dev/null 2>&1 && [ ! -f /etc/logrotate.d/remnanode ]; then
  cat > /etc/logrotate.d/remnanode <<LR
$LOG_DIR/*.log {
    size 100M
    rotate 3
    missingok
    notifempty
    compress
    copytruncate
}
LR
  CRON_LINE='15 * * * * /usr/sbin/logrotate /etc/logrotate.d/remnanode'
  ( crontab -l 2>/dev/null | grep -v 'logrotate.d/remnanode' || true; echo "$CRON_LINE" ) | crontab - 2>/dev/null || true
  green "logrotate: $LOG_DIR/*.log — ротация при 100M, архив (gzip), хранить 3 архива, проверка раз в час"
fi

# --- systemd ---
cat > "$SERVICE" <<UNIT
[Unit]
Description=ablocker - Xray abuse blocker (torrents + malware/botnet)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$BIN -c $INSTALL_DIR/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable ablocker >/dev/null 2>&1 || true
systemctl restart ablocker

sleep 1
green "Готово."
blue  "Статус:  systemctl status ablocker"
blue  "Логи:    journalctl -u ablocker -f"
blue  "Конфиг:  $INSTALL_DIR/config.yaml"
