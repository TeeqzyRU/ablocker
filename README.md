# ablocker

**Xray abuse blocker** для нод Remnawave/Xray. Форк
[tblocker](https://github.com/kutovoys/xray-torrent-blocker): делает всё то же
(банит торрент-абузеров по access.log), **плюс** банит юзеров, чьи устройства
заражены малварью/ботнетом (Vo1d / BadBox и т.п.).

## Как это работает

ablocker читает `access.log` Xray и:

1. **Торренты** — ловит тег `TORRENT` (нужен bittorrent-сниффинг в Xray +
   роутинг тега в blackhole) и временно банит IP. Как tblocker.
2. **Malware / botnet** — сверяет адрес назначения каждого коннекта с фидами
   C2/ботнет-индикаторов. Если устройство стучится на известную малварь-
   инфраструктуру — баним юзера.

> Важно: малварь не видна «на устройстве», она палится по трафику на известные
> C2-домены/IP. Поэтому нужен нормальный malware/C2 фид (abuse.ch URLhaus /
> Feodo Tracker / ThreatFox), а **не** обычный блок-лист рекламы — он Vo1d/BadBox
> не содержит. И статические листы ловят только известную инфраструктуру: свежие
> DGA-домены пройдут мимо.

## Установка

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/TeeqzyRU/ablocker/main/install.sh)
```

(репозиторий уже прописан — `TeeqzyRU/ablocker`)

Скрипт скачает релиз-бинарь (или соберёт из исходников, если есть Go),
положит конфиг в `/opt/ablocker/config.yaml`, поднимет systemd-сервис
`ablocker`.

## Релизы

Сборкой бинарей занимается goreleaser в GitHub Actions. Просто запушь тег:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

→ соберутся `linux/amd64` и `linux/arm64`, появится Release с tar.gz, и
`install.sh` их подхватит.

## Конфиг (`/opt/ablocker/config.yaml`)

Ключевые malware-параметры:

- `MalwareBlockEnabled` — вкл/выкл malware-блок.
- `MalwareDomainFeeds` / `MalwareIPFeeds` — список фидов (URL). Проверь их.
- `MalwareAction` — `ban` (длинный локальный бан IP, работает сразу) или
  `disable` (+ вебхук на панель, чтобы вырубить юзера на ВСЕХ нодах).
- `MalwareBlockDuration` — длина бана в минутах (по умолчанию 1440 = 24ч;
  короткий бан против ботнета бесполезен — бокс переподключится).
- `BlocklistReload` — как часто перечитывать фиды.

### Режим `disable` (рекомендуется для ботнета)

Чтобы вырубать заражённого юзера сразу на всех нодах, включи вебхук
(`SendWebhook: true` + `WebhookURL`). ablocker пошлёт POST с
`action: "malware_disable"` — а уже твой n8n/обработчик дёрнет API Remnawave и
задизейблит юзера. Сам ablocker в панель не ходит.

## Управление

```bash
systemctl status ablocker
journalctl -u ablocker -f
```

## Благодарности

Основано на [xray-torrent-blocker](https://github.com/kutovoys/xray-torrent-blocker)
(Sergey Kutovoy, MIT). Malware/botnet-детект и упаковка — наше.
