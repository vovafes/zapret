#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zapret-discord v1.2.0
Локальный инструмент обхода DPI-блокировок для Discord.
Репозиторий: https://github.com/vovafes/zapret
"""

import sys
import os
import ctypes
import json
import time
import threading
import urllib.request
from datetime import datetime

# ──────────────────────────────────────────────────────────────────────────────
# Константы
# ──────────────────────────────────────────────────────────────────────────────

VERSION    = "1.2.0"
CONFIG_URL = "https://raw.githubusercontent.com/vovafes/zapret/main/config.json"

DEFAULT_CONFIG: dict = {
    "target_domains": [
        "discord.com",
        "discordapp.com",
        "gateway.discord.gg",
        "discord.media",
        "cdn.discordapp.com",
    ],
    "split_position":   2,
    "desync_mode":      "split",
    "udp_fake_enabled": True,
}

# ──────────────────────────────────────────────────────────────────────────────
# Глобальное состояние
# ──────────────────────────────────────────────────────────────────────────────

_stats: dict   = {"intercepted": 0, "bypassed": 0, "voice_fixed": 0, "errors": 0}
_stats_lock    = threading.Lock()
_running: bool = True

# ──────────────────────────────────────────────────────────────────────────────
# Цветовые коды ANSI
# ──────────────────────────────────────────────────────────────────────────────

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ──────────────────────────────────────────────────────────────────────────────
# Права администратора
# ──────────────────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_and_exit() -> None:
    """
    Перезапустить скрипт с правами администратора через ShellExecuteW (UAC).
    """
    script = os.path.abspath(sys.argv[0])
    args   = " ".join(f'"{a}"' for a in sys.argv[1:])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {args}', None, 1
    )
    if ret <= 32:
        print(f"{RED}[ОШИБКА]{RESET} Не удалось получить права администратора (код {ret}).")
        print("Пожалуйста, запустите программу вручную от имени администратора.")
        input("Нажмите Enter для выхода...")
    sys.exit(0)

# ──────────────────────────────────────────────────────────────────────────────
# OTA — удалённая конфигурация
# ──────────────────────────────────────────────────────────────────────────────

def fetch_remote_config() -> tuple:
    """
    Загрузить config.json с репозитория vovafes/zapret на GitHub.
    Возвращает (config_dict, success: bool).
    """
    try:
        req = urllib.request.Request(
            CONFIG_URL,
            headers={
                "User-Agent":    f"zapret-discord/{VERSION}",
                "Cache-Control": "no-cache",
                "Pragma":        "no-cache",
            },
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8")

        cfg = json.loads(raw)

        required_keys = {"target_domains", "split_position", "desync_mode", "udp_fake_enabled"}
        missing = required_keys - set(cfg.keys())
        if missing:
            raise ValueError(f"Неполный конфиг — отсутствуют поля: {missing}")

        cfg["split_position"]   = int(cfg["split_position"])
        cfg["udp_fake_enabled"] = bool(cfg["udp_fake_enabled"])
        cfg["desync_mode"]      = str(cfg["desync_mode"]).lower()
        cfg["target_domains"]   = [str(d).lower() for d in cfg["target_domains"]]

        return cfg, True

    except Exception:
        return DEFAULT_CONFIG.copy(), False

# ──────────────────────────────────────────────────────────────────────────────
# Консольный UI
# ──────────────────────────────────────────────────────────────────────────────

def print_banner(config: dict, cloud_ok: bool) -> None:
    os.system("cls")

    sync_str = (
        f"{GREEN}OK  ·  vovafes/zapret{RESET}"
        if cloud_ok
        else f"{YELLOW}OFFLINE  ·  встроенный конфиг{RESET}"
    )
    udp_str  = f"{GREEN}Включён{RESET}" if config["udp_fake_enabled"] else f"{RED}Выключен{RESET}"
    mode_str = f"{YELLOW}{config['desync_mode'].upper()}{RESET}"
    dom_list = config["target_domains"]
    dom_str  = ", ".join(dom_list[:3])
    if len(dom_list) > 3:
        dom_str += f" {DIM}+{len(dom_list) - 3} ещё{RESET}"

    W    = 66
    line = f"{CYAN}{'═' * W}{RESET}"
    sep  = f"{CYAN}{'─' * W}{RESET}"

    print(line)
    print(f"{CYAN}{BOLD}  zapret-discord{RESET}  v{VERSION}"
          f"   │   Обход DPI-блокировок Discord")
    print(line)
    print(f"  {'Облачный конфиг':<22}: {sync_str}")
    print(f"  {'Режим десинхр.':<22}: {mode_str}  │  позиция сплита: "
          f"{YELLOW}{config['split_position']}{RESET} байт")
    print(f"  {'UDP / Голос (RTC)':<22}: {udp_str}  "
          f"{DIM}(порты 50000–65535){RESET}")
    print(f"  {'Целевые домены':<22}: {dom_str}")
    print(sep)
    print(f"  Нажмите {BOLD}Ctrl+C{RESET} для корректной остановки\n")
    print(f"  {DIM}{'─' * (W - 2)}{RESET}")
    print(f"  Лог работы:\n")


def log(msg: str) -> None:
    ts   = datetime.now().strftime("%H:%M:%S")
    line = f"  [{DIM}{ts}{RESET}] {msg}"
    print(line)

# ──────────────────────────────────────────────────────────────────────────────
# Анализ пакетов
# ──────────────────────────────────────────────────────────────────────────────

def is_tls_client_hello(data: bytes) -> bool:
    """
    Быстрая проверка сигнатуры TLS Handshake/ClientHello.

    TLS Record формат:
      Byte 0    : 0x16 — Content Type: Handshake
      Byte 1    : 0x03 — Major version (SSL/TLS 3.x)
      Byte 2    : 0x01/0x02/0x03 — Minor version (TLS 1.0/1.1/1.2+)
      Bytes 3-4 : record length
      Byte 5    : 0x01 — Handshake Type: ClientHello
    """
    return (
        len(data) >= 6
        and data[0] == 0x16
        and data[1] == 0x03
        and data[2] in (0x01, 0x02, 0x03)
        and data[5] == 0x01
    )


def payload_matches_domains(payload: bytes, domains: list) -> bool:
    """
    Искать доменное имя как байтовую подстроку внутри TLS ClientHello.
    SNI передаётся в открытом виде — прямой поиск работает без ASN.1-парсинга.
    """
    for domain in domains:
        try:
            if domain.encode("ascii") in payload:
                return True
        except (UnicodeEncodeError, AttributeError):
            continue
    return False

# ──────────────────────────────────────────────────────────────────────────────
# Обработка TCP — фрагментация TLS ClientHello
# ──────────────────────────────────────────────────────────────────────────────

def process_tcp(packet, config: dict, w) -> None:
    """
    Перехватить TLS ClientHello для целевого домена и применить десинхронизацию.

    Режим 'split':
      Разбить payload на два TCP-фрагмента и отправить по порядку.
      DPI видит неполный ClientHello в первом сегменте и не определяет SNI.

    Режим 'disorder':
      Отправить второй фрагмент ПЕРВЫМ (с скорректированным SEQ),
      затем первый. Большинство DPI-реализаций не переупорядочивают сегменты.
    """
    payload = bytes(packet.payload) if packet.payload else b""

    if not is_tls_client_hello(payload) or not payload_matches_domains(
        payload, config["target_domains"]
    ):
        w.send(packet, recalculate_checksum=True)
        return

    with _stats_lock:
        _stats["intercepted"] += 1

    pos      = config["split_position"]
    mode     = config["desync_mode"]
    base_seq = packet.tcp.seq_num

    if len(payload) <= pos:
        w.send(packet, recalculate_checksum=True)
        return

    part1 = payload[:pos]
    part2 = payload[pos:]

    if mode == "disorder":
        packet.payload     = part2
        packet.tcp.seq_num = (base_seq + pos) & 0xFFFFFFFF
        w.send(packet, recalculate_checksum=True)

        packet.payload     = part1
        packet.tcp.seq_num = base_seq
        w.send(packet, recalculate_checksum=True)

        log(
            f"{GREEN}[TCP DISORDER]{RESET}  TLS ClientHello → "
            f"фрагм.{YELLOW}②{RESET}({len(part2)} б) → "
            f"фрагм.{YELLOW}①{RESET}({len(part1)} б)"
        )
    else:
        packet.payload     = part1
        packet.tcp.seq_num = base_seq
        w.send(packet, recalculate_checksum=True)

        packet.payload     = part2
        packet.tcp.seq_num = (base_seq + pos) & 0xFFFFFFFF
        w.send(packet, recalculate_checksum=True)

        log(
            f"{GREEN}[TCP SPLIT]{RESET}     TLS ClientHello → "
            f"фрагм.{YELLOW}①{RESET}({len(part1)} б) + "
            f"фрагм.{YELLOW}②{RESET}({len(part2)} б)"
        )

    with _stats_lock:
        _stats["bypassed"] += 1

# ──────────────────────────────────────────────────────────────────────────────
# Обработка UDP — обфускация голосовых каналов
# ──────────────────────────────────────────────────────────────────────────────

def process_udp(packet, w) -> None:
    """
    Вставить фиктивный UDP-пакет перед настоящим голосовым пакетом.
    Сбрасывает состояние UDP-трекера DPI без влияния на качество голоса
    (SRTP/Opus FEC устойчив к единичным потерям).
    """
    real_payload = bytes(packet.payload) if packet.payload else b""

    if len(real_payload) < 4:
        w.send(packet, recalculate_checksum=True)
        return

    packet.payload = b"\x00\xFF\xAA\x55\x00\xFF\xAA\x55"
    w.send(packet, recalculate_checksum=True)

    packet.payload = real_payload
    w.send(packet, recalculate_checksum=True)

    with _stats_lock:
        _stats["voice_fixed"] += 1

# ──────────────────────────────────────────────────────────────────────────────
# Основной цикл WinDivert
# ──────────────────────────────────────────────────────────────────────────────

def run_filter(config: dict) -> None:
    global _running

    try:
        import pydivert
    except ImportError:
        log(
            f"{RED}[КРИТИЧНО]{RESET} Библиотека pydivert не установлена.\n"
            f"           Выполните: {YELLOW}pip install pydivert{RESET}"
        )
        time.sleep(6)
        return

    tcp_part = "outbound and tcp.DstPort == 443"
    udp_part = "outbound and udp and udp.DstPort >= 50000 and udp.DstPort <= 65535"

    flt = f"({tcp_part}) or ({udp_part})" if config.get("udp_fake_enabled", True) else tcp_part

    log(f"WinDivert фильтр: {DIM}{flt}{RESET}")

    try:
        with pydivert.WinDivert(flt) as w:
            log(f"{GREEN}[АКТИВЕН]{RESET}  Перехват трафика Discord запущен.")

            for packet in w:
                if not _running:
                    try:
                        w.send(packet, recalculate_checksum=True)
                    except Exception:
                        pass
                    break

                try:
                    if packet.tcp:
                        process_tcp(packet, config, w)
                    elif packet.udp and config.get("udp_fake_enabled", True):
                        process_udp(packet, w)
                    else:
                        w.send(packet, recalculate_checksum=True)

                except Exception:
                    with _stats_lock:
                        _stats["errors"] += 1
                    try:
                        w.send(packet, recalculate_checksum=True)
                    except Exception:
                        pass

    except OSError as exc:
        log(f"{RED}[ОШИБКА WinDivert]{RESET} {exc}")
        log(
            f"Убедитесь, что {YELLOW}WinDivert.dll{RESET} и "
            f"{YELLOW}WinDivert64.sys{RESET} находятся рядом с программой."
        )
        time.sleep(8)

    except KeyboardInterrupt:
        raise

# ──────────────────────────────────────────────────────────────────────────────
# Поток статистики
# ──────────────────────────────────────────────────────────────────────────────

def stats_worker() -> None:
    while _running:
        time.sleep(30)
        if not _running:
            break
        with _stats_lock:
            s = dict(_stats)
        log(
            f"{CYAN}[СТАТИСТИКА]{RESET}  "
            f"Перехвачено: {YELLOW}{s['intercepted']}{RESET}  │  "
            f"Обойдено: {GREEN}{s['bypassed']}{RESET}  │  "
            f"Голос: {GREEN}{s['voice_fixed']}{RESET}  │  "
            f"Ошибок: {RED}{s['errors']}{RESET}"
        )

# ──────────────────────────────────────────────────────────────────────────────
# Точка входа
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    global _running

    if not is_admin():
        print(f"\n  {YELLOW}[UAC]{RESET} Требуются права администратора. Запрос UAC...")
        elevate_and_exit()
        return

    print(f"\n  {CYAN}{BOLD}zapret-discord{RESET}  v{VERSION}\n")
    print(f"  Синхронизация конфига с {CYAN}vovafes/zapret{RESET} ...", end="", flush=True)
    config, cloud_ok = fetch_remote_config()
    status_str = f"{GREEN}OK{RESET}" if cloud_ok else f"{YELLOW}OFFLINE (fallback){RESET}"
    print(f" {status_str}\n")

    print_banner(config, cloud_ok)

    if not cloud_ok:
        log(
            f"{YELLOW}[ВНИМАНИЕ]{RESET}  GitHub недоступен. "
            f"Используется встроенная конфигурация (версия {VERSION})."
        )
    else:
        log(
            f"{GREEN}[КОНФИГ]{RESET}    Облачный конфиг успешно загружен "
            f"с {CYAN}vovafes/zapret{RESET}."
        )

    threading.Thread(target=stats_worker, daemon=True).start()

    try:
        run_filter(config)
    except KeyboardInterrupt:
        _running = False
        print()
        log(f"{YELLOW}[СТОП]{RESET}  Получен сигнал остановки (Ctrl+C)...")
        log(f"        Закрываю хэндл WinDivert...")
        log(f"{GREEN}[OK]{RESET}    Фильтр деактивирован. Интернет-соединение восстановлено.")
        log(f"        До свидания!")
        time.sleep(1)
        sys.exit(0)


if __name__ == "__main__":
    main()
