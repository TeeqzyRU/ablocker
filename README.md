# ablocker

Xray abuse blocker для нод Remnawave / Xray. Блокирует не только торрент-абузеров
(как [tblocker](https://github.com/kutovoys/xray-torrent-blocker)), но и устройства,
заражённые малварью или ботнетом (Vo1d / BadBox и подобные).

## Возможности

- **Торрент-блокировка** — детект по тегу `TORRENT` в access.log Xray (требует
  bittorrent-сниффинга и роутинга в blackhole), временный бан IP.
- **Malware / botnet** — сверка адресов назначения с фидами C2/malware-индикаторов;
  бан устройств, обращающихся к известной вредоносной инфраструктуре.
- Фаервол на выбор: `iptables` или `nftables`.
- Временные баны с автоматическим разбаном и сохранением между перезапусками.
- Вебхуки (для отключения пользователя через панель в режиме `disable`).

## Как это работает

ablocker читает `access.log` Xray построчно и реагирует на два типа событий:

1. **Торренты** — строки с тегом `TORRENT` → временный бан исходного IP
   (по умолчанию 10 минут).
2. **Malware / botnet** — адрес назначения сверяется с загруженными фидами
   индикаторов. Совпадение → бан IP (по умолчанию 24 часа, так как заражённое
   устройство переподключается после короткого бана).

Заражение определяется по трафику: устройство обращается к известным
C2/ботнет-доменам или IP. Статические фиды покрывают только известную
инфраструктуру — свежие DGA-домены могут не попадать в списки.

## Установка

```bash
curl -fsSL https://raw.githubusercontent.com/TeeqzyRU/ablocker/main/install.sh -o ablocker-install.sh && bash ablocker-install.sh
```

Требуются права root. Установщик скачивает бинарь из последнего релиза (или
собирает из исходников при наличии Go), создаёт конфиг `/opt/ablocker/config.yaml`
и systemd-сервис `ablocker`.

## Конфигурация

Файл `/opt/ablocker/config.yaml`. Основные параметры:

| Параметр | Назначение |
|---|---|
| `LogFile` | Путь к access.log ноды |
| `BlockMode` | `iptables` или `nft` |
| `BlockDuration` | Длительность бана за торрент (минуты) |
| `MalwareBlockEnabled` | Включение malware/botnet-блокировки |
| `MalwareDomainFeeds` / `MalwareIPFeeds` | Списки фидов индикаторов (домены и IP) |
| `MalwareAction` | `ban` (локальный бан IP) или `disable` (вебхук на панель) |
| `MalwareBlockDuration` | Длительность malware-бана (минуты) |
| `BlocklistReload` | Интервал обновления фидов |

Фиды должны содержать malware/C2-индикаторы (например, [abuse.ch](https://abuse.ch):
URLhaus, Feodo Tracker, ThreatFox, SSLBL), а не обычные блок-листы рекламы —
последние приведут к ложным банам обычных пользователей.

## Режим disable

Для отключения самого пользователя (а не только бана одного IP на одной ноде)
используется `MalwareAction: disable` вместе с вебхуком (`SendWebhook` +
`WebhookURL`). ablocker отправляет POST с действием `malware_disable`; обработчик
на стороне панели (например, n8n) отключает пользователя через API Remnawave.

## Сборка релизов

Бинари собираются автоматически через GitHub Actions (goreleaser). Для выпуска
новой версии:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Соберутся `linux/amd64` и `linux/arm64`, в разделе Releases появятся архивы.

## Управление

```bash
systemctl status ablocker      # состояние сервиса
journalctl -u ablocker -f      # логи в реальном времени
```

## Благодарности

Проект основан на [xray-torrent-blocker](https://github.com/kutovoys/xray-torrent-blocker)
(автор Sergey Kutovoy, лицензия MIT). Добавлены детект malware/botnet и интеграция
фидов индикаторов.
