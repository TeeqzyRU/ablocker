#!/usr/bin/env bash
#
# ablocker installer
#
# Интерактивно (спросит лог, фаервол, срок бана, malware):
#   curl -fsSL https://cdn.jsdelivr.net/gh/TeeqzyRU/ablocker@main/install.sh -o ablocker-install.sh && bash ablocker-install.sh
#   (если jsDelivr недоступен: https://raw.githubusercontent.com/TeeqzyRU/ablocker/main/install.sh)
#
# Без вопросов, дефолты (лог remnanode, iptables, malware on, бан 30 дней):
#   bash ablocker-install.sh -y
#
# Примеры:
#   bash ablocker-install.sh -y --duration 1440
#   bash ablocker-install.sh --fw nft --logfile /var/log/xray/access.log
#   bash ablocker-install.sh --uninstall
#
set -euo pipefail

GH_REPO="${GH_REPO:-TeeqzyRU/ablocker}"
INSTALL_DIR="/opt/ablocker"
BIN="$INSTALL_DIR/ablocker"
SERVICE="/etc/systemd/system/ablocker.service"

red()   { printf "\033[31m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
blue()  { printf "\033[34m%s\033[0m\n" "$*"; }
die()   { red "$*"; exit 1; }
trap 'red "Ошибка на строке $LINENO"' ERR

usage() { cat <<'H'
Флаги (или переменные окружения):
  -y, --yes               без вопросов                      [ABLOCKER_YES=1]
  --duration MIN          бан за торренты, минут            [ABLOCKER_DURATION]
  --malware-duration MIN  бан за malware, минут             [ABLOCKER_MW_DURATION]
  --logfile PATH          путь к access.log                 [ABLOCKER_LOGFILE]
  --fw iptables|nft       фаервол                           [ABLOCKER_FW]
  --no-malware            выключить malware-блок            [ABLOCKER_MALWARE=0]
  --version vX.Y.Z        поставить конкретный релиз        [ABLOCKER_VERSION]
  --uninstall             удалить ablocker с ноды

Повторный запуск на ноде обновляет бинарь, а в config.yaml меняет
только то, что задано явно (флагом или ответом на вопрос).
H
}

# --- аргументы / env ---
YES="${ABLOCKER_YES:-0}"
DURATION="${ABLOCKER_DURATION:-}"
MW_DURATION="${ABLOCKER_MW_DURATION:-}"
LOGFILE="${ABLOCKER_LOGFILE:-}"
FW="${ABLOCKER_FW:-}"
MALWARE="${ABLOCKER_MALWARE:-}"
VERSION="${ABLOCKER_VERSION:-}"
UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)           YES=1 ;;
    --duration)         DURATION="${2:?--duration требует число минут}"; shift ;;
    --malware-duration) MW_DURATION="${2:?--malware-duration требует число минут}"; shift ;;
    --logfile)          LOGFILE="${2:?--logfile требует путь}"; shift ;;
    --fw)               FW="${2:?--fw требует iptables|nft}"; shift ;;
    --no-malware)       MALWARE=0 ;;
    --version)          VERSION="${2:?--version требует тег, напр. v1.0.3}"; shift ;;
    --uninstall)        UNINSTALL=1 ;;
    -h|--help)          usage; exit 0 ;;
    *)                  usage; die "Неизвестный флаг: $1" ;;
  esac
  shift
done

is_num() { case "${1:-}" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
if [ -n "$DURATION" ];    then is_num "$DURATION"    || die "--duration: нужно число минут"; fi
if [ -n "$MW_DURATION" ]; then is_num "$MW_DURATION" || die "--malware-duration: нужно число минут"; fi
case "$FW" in ''|iptables|nft) ;; *) die "--fw: только iptables или nft" ;; esac

[ "$(id -u)" -eq 0 ] || die "Запусти от root (sudo)."

# --- удаление ---
if [ "$UNINSTALL" = 1 ]; then
  blue "Удаляю ablocker..."
  systemctl disable --now ablocker 2>/dev/null || true
  systemctl disable --now ablocker-logrotate.timer 2>/dev/null || true
  rm -f "$SERVICE" /etc/systemd/system/ablocker-logrotate.service /etc/systemd/system/ablocker-logrotate.timer
  systemctl daemon-reload 2>/dev/null || true
  iptables -t raw -D PREROUTING -j ABLOCKER_BLOCKED 2>/dev/null || true
  iptables -t raw -F ABLOCKER_BLOCKED 2>/dev/null || true
  iptables -t raw -X ABLOCKER_BLOCKED 2>/dev/null || true
  nft delete table inet ablocker 2>/dev/null || true
  rm -rf "$INSTALL_DIR"
  green "Удалено. /etc/logrotate.d/remnanode оставил (ротация логов ноде полезна);"
  green "не нужен — убери: rm -f /etc/logrotate.d/remnanode"
  exit 0
fi

command -v systemctl >/dev/null || die "Нужен systemd (systemctl не найден)."

# --- архитектура ---
case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "Неподдерживаемая архитектура: $(uname -m)" ;;
esac
blue "Архитектура: $ARCH"

# --- пакеты ---
install_pkg() {
  if   command -v apt-get >/dev/null; then apt-get update -qq >/dev/null 2>&1 || true; apt-get install -y "$@" >/dev/null
  elif command -v dnf     >/dev/null; then dnf install -y "$@" >/dev/null
  elif command -v yum     >/dev/null; then yum install -y "$@" >/dev/null
  else red "Не нашёл пакетный менеджер — поставь вручную: $*"; return 1; fi
}
command -v conntrack >/dev/null || { blue "Ставлю conntrack..."; install_pkg conntrack || install_pkg conntrack-tools || true; }

systemctl stop ablocker 2>/dev/null || true
mkdir -p "$INSTALL_DIR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# --- тег релиза: сначала по редиректу github.com (работает там, где api.github.com режется) ---
get_latest_tag() {
  local eff
  eff="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$GH_REPO/releases/latest" 2>/dev/null || true)"
  case "$eff" in
    */tag/*) printf '%s\n' "${eff##*/}"; return 0 ;;
  esac
  curl -fsSL "https://api.github.com/repos/$GH_REPO/releases/latest" 2>/dev/null \
    | grep -m1 '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

download_release() {
  local tag="$1" file url
  file="ablocker-${tag}-linux-${ARCH}.tar.gz"
  url="https://github.com/$GH_REPO/releases/download/${tag}/${file}"
  blue "Качаю $url"
  curl -fsSL "$url" -o "$TMP/$file" || return 1
  tar -xzf "$TMP/$file" -C "$TMP" || return 1
  [ -f "$TMP/ablocker" ] || return 1
  install -m 0755 "$TMP/ablocker" "$BIN"
  if [ -f "$TMP/config.yaml.default" ]; then cp "$TMP/config.yaml.default" "$INSTALL_DIR/config.yaml.default"; fi
  return 0
}

build_from_source() {
  command -v go >/dev/null || return 1
  blue "Релиз недоступен — собираю из исходников..."
  git clone --depth 1 "https://github.com/$GH_REPO.git" "$TMP/src" >/dev/null 2>&1 || return 1
  ( cd "$TMP/src" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BIN" . ) || return 1
  cp "$TMP/src/config.yaml.default" "$INSTALL_DIR/config.yaml.default"
}

TAG="${VERSION:-$(get_latest_tag || true)}"
if [ -n "${TAG:-}" ] && download_release "$TAG"; then
  green "Бинарь установлен из релиза $TAG"
elif build_from_source; then
  green "Бинарь собран из исходников"
else
  die "Не скачал релиз и не собрал из исходников. Проверь доступ к github.com или задай --version vX.Y.Z"
fi

# --- config.yaml.default: фолбэк, если не приехал с релизом ---
if [ ! -f "$INSTALL_DIR/config.yaml.default" ]; then
  blue "config.yaml.default не пришёл с релизом — качаю из репозитория..."
  curl -fsSL "https://cdn.jsdelivr.net/gh/$GH_REPO@main/config.yaml.default" -o "$INSTALL_DIR/config.yaml.default" \
    || curl -fsSL "https://raw.githubusercontent.com/$GH_REPO/main/config.yaml.default" -o "$INSTALL_DIR/config.yaml.default" \
    || die "Не удалось получить config.yaml.default."
fi

FRESH=0
if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
  cp "$INSTALL_DIR/config.yaml.default" "$INSTALL_DIR/config.yaml"
  FRESH=1
  green "Создан $INSTALL_DIR/config.yaml"
else
  blue "config.yaml уже есть — обновлю только явно заданное."
fi

cfg_get() { sed -n "s/^$1:[[:space:]]*//p" "$INSTALL_DIR/config.yaml" | head -1 | sed 's/[[:space:]]*#.*//; s/^"//; s/"[[:space:]]*$//'; }
cfg_set() { sed -i "s|^$1:.*|$1: $2|" "$INSTALL_DIR/config.yaml"; }

# --- вопросы (если интерактивно и не -y) ---
if [ "$YES" != 1 ] && [ -t 0 ]; then
  CUR="$(cfg_get LogFile)"
  read -rp "Путь к access.log [${CUR:-/var/log/remnanode/access.log}]: " a || true
  if [ -n "${a:-}" ]; then LOGFILE="$a"; fi

  CUR="$(cfg_get BlockMode)"
  read -rp "Firewall iptables/nft [${CUR:-iptables}]: " a || true
  case "${a:-}" in
    iptables|nft) FW="$a" ;;
    "") ;;
    *) red "  не понял '$a' — оставляю как было" ;;
  esac

  CUR_BD="$(cfg_get BlockDuration)"
  echo "Срок бана за торренты (в конфиге сейчас: ${CUR_BD:-?} мин):"
  echo "  1) 60 (час)   2) 1440 (сутки)   3) 43200 (30 дней)   4) своё число"
  if [ "$FRESH" = 1 ]; then PROMPT="Выбор [3]: "; DEF="3"; else PROMPT="Выбор [Enter — не менять]: "; DEF=""; fi
  read -rp "$PROMPT" a || true
  a="${a:-$DEF}"
  case "$a" in
    1) DURATION=60 ;;
    2) DURATION=1440 ;;
    3) DURATION=43200 ;;
    4) read -rp "  минут: " DURATION || true
       is_num "${DURATION:-}" || { red "  не число — не меняю"; DURATION=""; } ;;
    "") ;;
    *) red "  не понял — не меняю" ;;
  esac

  CUR="$(cfg_get MalwareBlockEnabled)"
  read -rp "Блокировка malware/botnet? y/n [${CUR:-true}]: " a || true
  case "${a:-}" in y|Y) MALWARE=1 ;; n|N) MALWARE=0 ;; esac
fi

# --- применяем настройки ---
if [ "$FRESH" = 1 ]; then
  DURATION="${DURATION:-43200}"
fi
if [ -n "${LOGFILE:-}" ]; then cfg_set LogFile "\"$LOGFILE\""; fi
if [ -n "${FW:-}" ]; then cfg_set BlockMode "\"$FW\""; fi
if [ -n "${DURATION:-}" ]; then
  cfg_set BlockDuration "$DURATION"
  MW_DURATION="${MW_DURATION:-$DURATION}"
fi
if [ -n "${MW_DURATION:-}" ]; then cfg_set MalwareBlockDuration "$MW_DURATION"; fi
case "${MALWARE:-}" in
  1) cfg_set MalwareBlockEnabled true ;;
  0) cfg_set MalwareBlockEnabled false ;;
esac

# --- logrotate + systemd-таймер (cron не нужен) ---
LOGPATH="$(cfg_get LogFile)"
LOG_DIR="$(dirname "${LOGPATH:-/var/log/remnanode/access.log}")"
command -v logrotate >/dev/null 2>&1 || install_pkg logrotate || true
if command -v logrotate >/dev/null 2>&1; then
  if [ ! -f /etc/logrotate.d/remnanode ]; then
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
    green "logrotate: $LOG_DIR/*.log — ротация при 100M, 3 архива"
  else
    blue "logrotate-конфиг уже есть — не трогаю."
  fi
  LR_BIN="$(command -v logrotate)"
  cat > /etc/systemd/system/ablocker-logrotate.service <<UNIT
[Unit]
Description=logrotate for node logs (ablocker)

[Service]
Type=oneshot
ExecStart=$LR_BIN /etc/logrotate.d/remnanode
UNIT
  cat > /etc/systemd/system/ablocker-logrotate.timer <<'UNIT'
[Unit]
Description=Hourly logrotate for node logs (ablocker)

[Timer]
OnCalendar=*-*-* *:15:00
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now ablocker-logrotate.timer >/dev/null 2>&1 || true
  green "Ротация: systemd-таймер каждый час в :15 (cron не требуется)."
else
  red "logrotate не установился — ротацию логов настрой вручную."
fi

# --- systemd unit ---
cat > "$SERVICE" <<UNIT
[Unit]
Description=ablocker - Xray abuse blocker (torrents + malware/botnet)
Documentation=https://github.com/$GH_REPO
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
if ! systemctl restart ablocker; then
  red "ablocker не запустился. Последние логи:"
  journalctl -u ablocker -n 20 --no-pager || true
  exit 1
fi

# --- самопроверка ---
sleep 2
if systemctl is-active --quiet ablocker; then
  green "Готово — ablocker работает."
  journalctl -u ablocker -n 50 --no-pager | grep -m1 "Malware blocking enabled" || true
  blue "Конфиг: BlockDuration=$(cfg_get BlockDuration) мин, MalwareBlockDuration=$(cfg_get MalwareBlockDuration) мин, BlockMode=$(cfg_get BlockMode)"
  blue "Логи:   journalctl -u ablocker -f"
  blue "Файл:   $INSTALL_DIR/config.yaml"
else
  red "ablocker НЕ активен после старта. Последние логи:"
  journalctl -u ablocker -n 20 --no-pager || true
  exit 1
fi
