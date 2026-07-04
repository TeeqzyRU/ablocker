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
- Хелперы `ablocker-bans` (сводка) и `ablocker-unban <IP>` (полный разбан).
- Инсталлер сам настраивает ротацию логов ноды (logrotate + systemd-таймер).

## Как это работает

ablocker читает `access.log` Xray построчно и реагирует на два типа событий:

1. **Торренты** — строки с тегом `TORRENT` → временный бан исходного IP.
2. **Malware / botnet** — адрес назначения сверяется с загруженными фидами
   индикаторов. Совпадение → бан IP (заражённое устройство переподключается
   после короткого бана, поэтому баны длинные).

Заражение определяется по трафику: устройство обращается к известным
C2/ботнет-доменам или IP. Статические фиды покрывают только известную
инфраструктуру — свежие DGA-домены могут не попадать в списки.

## Установка

Интерактивно (спросит путь к логу, фаервол, срок бана, malware):

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/TeeqzyRU/ablocker@main/install.sh -o ablocker-install.sh && bash ablocker-install.sh
```

Если jsDelivr недоступен — то же самое через
`https://raw.githubusercontent.com/TeeqzyRU/ablocker/main/install.sh`.

Без вопросов, с дефолтами (лог remnanode, iptables, malware on, бан 30 дней):

```bash
bash ablocker-install.sh -y
```

### Флаги инсталлера

| Флаг | Переменная окружения | Назначение |
|---|---|---|
| `-y`, `--yes` | `ABLOCKER_YES=1` | без вопросов |
| `--duration MIN` | `ABLOCKER_DURATION` | бан за торренты, минут |
| `--malware-duration MIN` | `ABLOCKER_MW_DURATION` | бан за malware, минут |
| `--logfile PATH` | `ABLOCKER_LOGFILE` | путь к access.log |
| `--fw iptables\|nft` | `ABLOCKER_FW` | фаервол |
| `--no-malware` | `ABLOCKER_MALWARE=0` | выключить malware-блок |
| `--version vX.Y.Z` | `ABLOCKER_VERSION` | поставить конкретный релиз |
| `--uninstall` | — | удалить ablocker с ноды |

Примеры:

```bash
bash ablocker-install.sh -y --duration 1440
bash ablocker-install.sh --fw nft --logfile /var/log/xray/access.log
bash ablocker-install.sh --uninstall
```

Повторный запуск на ноде обновляет бинарь, а в `config.yaml` меняет только то,
что задано явно (флагом или ответом на вопрос) — остальные настройки не трогает.

Требуются права root и systemd. Инсталлер скачивает бинарь из последнего релиза
(или собирает из исходников при наличии Go), создаёт `/opt/ablocker/config.yaml`,
systemd-сервис `ablocker`, хелперы и ротацию логов (100M, 3 архива, проверка
раз в час через systemd-таймер — cron не нужен).

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

После правки конфига — `systemctl restart ablocker` (конфиг читается при старте).

Фиды должны содержать malware/C2-индикаторы (например, [abuse.ch](https://abuse.ch):
URLhaus, ThreatFox, Feodo Tracker), а не обычные блок-листы рекламы — последние
приведут к ложным банам обычных пользователей. Из коробки включены: URLhaus и
ThreatFox hostfile (домены), Feodo Tracker и почасовое
[зеркало всех активных ThreatFox IP](https://github.com/elliotwutingfeng/ThreatFox-IOC-IPs)
через jsDelivr (~23k адресов, доступно и с РФ-нод). IP-фиды понимают форматы
`IP`, `IP:port` и CSV-строки, включая экспорты ThreatFox с кавычками. SSLBL
IP-блэклист закрыт abuse.ch в январе 2025 и из дефолтов удалён.

## Управление

```bash
ablocker-bans            # сводка: статус, настройки, активные баны, счётчики за сегодня
ablocker-unban 1.2.3.4   # полный разбан IP (json + фаервол + рестарт)
```

Подробнее:

```bash
systemctl status ablocker                                    # состояние сервиса
journalctl -u ablocker -f                                    # логи в реальном времени
journalctl -u ablocker --no-pager | grep "(torrent)"         # история банов за торренты
journalctl -u ablocker --no-pager | grep "MALWARE hit"       # история malware-хитов
cat /opt/ablocker/blocked_ips.json                           # активные баны (сырой JSON)
iptables -t raw -L ABLOCKER_BLOCKED -n -v                    # правила фаервола (или: nft list table inet ablocker)
```

Проверка, что применились настройки (главная команда после установки/правок):

```bash
systemctl is-active ablocker && journalctl -u ablocker --no-pager | grep "Malware blocking enabled" | tail -1
```

Тест механики бана безопасным IP (RFC 5737):

```bash
echo "$(date '+%Y/%m/%d %H:%M:%S') from 203.0.113.77:54321 accepted tcp:test.invalid:443 [inbound >> TORRENT] email: testuser" >> /var/log/remnanode/access.log
journalctl -u ablocker -n 5 --no-pager    # ждём "blocked ... (torrent)"
ablocker-unban 203.0.113.77               # снять тестовый бан
```

## Режим disable

Для отключения самого пользователя (а не только бана одного IP на одной ноде)
используется `MalwareAction: disable` вместе с вебхуком (`SendWebhook` +
`WebhookURL`). ablocker отправляет POST с действием `malware_disable`; обработчик
на стороне панели (например, n8n) отключает пользователя через API Remnawave.

## Сборка релизов

Бинари собираются автоматически через GitHub Actions (goreleaser). Для выпуска
новой версии:

```bash
git tag v1.0.5
git push origin v1.0.5
```

Соберутся `linux/amd64` и `linux/arm64`, в разделе Releases появятся архивы.

## Благодарности

Проект основан на [xray-torrent-blocker](https://github.com/kutovoys/xray-torrent-blocker)
(автор Sergey Kutovoy, лицензия MIT). Добавлены детект malware/botnet и интеграция
фидов индикаторов.
