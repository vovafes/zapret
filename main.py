#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zapret-discord v2.0.0
Локальный инструмент обхода DPI-блокировок для Discord.
Репозиторий: https://github.com/vovafes/zapret
"""

import sys
import os
import ctypes
import json
import random
import time
import threading
import urllib.request
from datetime import datetime

# ──────────────────────────────────────────────────────────────────────────────
# Константы
# ──────────────────────────────────────────────────────────────────────────────

VERSION    = "2.0.0"
CONFIG_URL = "https://raw.githubusercontent.com/vovafes/zapret/main/config.json"

# Домены-приманки для фейковых ClientHello (не должны совпадать с реальной целью)
DECOY_SNI_POOL = [
    b"www.google.com",
    b"www.microsoft.com",
    b"www.cloudflare.com",
    b"www.apple.com",
]

DEFAULT_CONFIG: dict = {
    "target_domains": [
        "discord.com",
        "discordapp.com",
        "discordapp.net",
        "gateway.discord.gg",
        "discord.media",
        "cdn.discordapp.com",
        "youtube.com",
        "youtube-nocookie.com",
        "googlevideo.com",
        "ytimg.com",
        "ggpht.com",
        "instagram.com",
        "cdninstagram.com",
        "fbcdn.net",
        "facebook.com",
        "fb.com",
        "twitter.com",
        "x.com",
        "twimg.com",
        "whatsapp.com",
        "whatsapp.net",
        "signal.org",
        "whispersystems.org",
        "linkedin.com",
        "licdn.com",
        "viber.com",
        "snapchat.com",
        "sc-cdn.net",
        "twitch.tv",
        "ttvnw.net",
        "jtvnw.net",
        "roblox.com",
        "rbxcdn.com",
        "tiktok.com",
        "tiktokcdn.com",
        "tiktokv.com",
        "musical.ly",
    ],
    # desync_mode: "fake_multisplit" (по умолч.) | "multisplit" | "split" | "disorder"
    "desync_mode":          "fake_multisplit",
    "split_position":       2,      # используется только режимами "split"/"disorder"
    "fragment_count_min":   3,      # многосегментная фрагментация: мин. число частей
    "fragment_count_max":   7,      # максимум частей
    "randomize_fragments":  True,   # случайные позиции разрыва при каждом ClientHello
    "shuffle_fragment_order": True, # отправлять сегменты не по порядку
    "fake_packet_enabled":  True,   # инъекция фейкового ClientHello перед реальным
    "fake_packet_count":    1,      # сколько фейковых пакетов отправлять
    "fake_packet_ttl":      4,      # TTL фейка — гарантированно не доходит до сервера
    "udp_fake_enabled":     True,
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

        if "target_domains" not in cfg or "desync_mode" not in cfg:
            raise ValueError("Неполный конфиг — отсутствуют обязательные поля")

        # Мягкое слияние: неизвестные/отсутствующие поля берём из DEFAULT_CONFIG,
        # чтобы старый удалённый config.json не ломал новый клиент и наоборот.
        merged = DEFAULT_CONFIG.copy()
        merged.update(cfg)

        merged["split_position"]         = int(merged["split_position"])
        merged["udp_fake_enabled"]       = bool(merged["udp_fake_enabled"])
        merged["desync_mode"]            = str(merged["desync_mode"]).lower()
        merged["target_domains"]         = [str(d).lower() for d in merged["target_domains"]]
        merged["fragment_count_min"]     = max(2, int(merged["fragment_count_min"]))
        merged["fragment_count_max"]     = max(
            merged["fragment_count_min"], int(merged["fragment_count_max"])
        )
        merged["randomize_fragments"]    = bool(merged["randomize_fragments"])
        merged["shuffle_fragment_order"] = bool(merged["shuffle_fragment_order"])
        merged["fake_packet_enabled"]    = bool(merged["fake_packet_enabled"])
        merged["fake_packet_count"]      = max(0, int(merged["fake_packet_count"]))
        merged["fake_packet_ttl"]        = max(1, min(255, int(merged["fake_packet_ttl"])))

        return merged, True

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
    fake_str = (
        f"{GREEN}Вкл. ×{config['fake_packet_count']} (TTL {config['fake_packet_ttl']}){RESET}"
        if config["fake_packet_enabled"]
        else f"{RED}Выключен{RESET}"
    )
    frag_str = f"{YELLOW}{config['fragment_count_min']}–{config['fragment_count_max']}{RESET}"
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
    print(f"  {'Режим десинхр.':<22}: {mode_str}")
    print(f"  {'Фрагментов на Hello':<22}: {frag_str}")
    print(f"  {'Фейковый ClientHello':<22}: {fake_str}")
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
# TTL — общий хелпер для IPv4/IPv6
# ──────────────────────────────────────────────────────────────────────────────

def get_ttl(packet):
    if packet.ipv4:
        return packet.ipv4.ttl
    if packet.ipv6:
        return packet.ipv6.hop_limit
    return None


def set_ttl(packet, ttl: int) -> None:
    if packet.ipv4:
        packet.ipv4.ttl = ttl
    elif packet.ipv6:
        packet.ipv6.hop_limit = ttl

# ──────────────────────────────────────────────────────────────────────────────
# Фейковый ClientHello (TTL-trick)
# ──────────────────────────────────────────────────────────────────────────────

def build_fake_clienthello(real_payload: bytes) -> bytes:
    """
    Собрать поддельный TLS ClientHello того же размера, что и настоящий:
    сохраняет TLS-заголовок (байты 0-5), чтобы пройти сигнатурную проверку
    DPI, но заполняет остальное случайным мусором с подставным SNI из
    DECOY_SNI_POOL — реальный домен цели в пакет не попадает.
    Пакет отправляется с заниженным TTL и до сервера физически не доходит,
    поэтому на соединение он не влияет — только сбивает трекинг DPI.
    """
    decoy   = random.choice(DECOY_SNI_POOL)
    garbage = bytearray(random.randbytes(len(real_payload)))
    garbage[:6] = real_payload[:6]  # валидный TLS Handshake/ClientHello заголовок

    if len(decoy) < len(garbage) - 6:
        offset = random.randint(6, len(garbage) - len(decoy))
        garbage[offset:offset + len(decoy)] = decoy

    return bytes(garbage)


def send_fake_packets(packet, real_payload: bytes, base_seq: int, config: dict, w) -> None:
    original_ttl = get_ttl(packet)
    if original_ttl is None:
        return

    for _ in range(config["fake_packet_count"]):
        set_ttl(packet, config["fake_packet_ttl"])
        packet.payload     = build_fake_clienthello(real_payload)
        packet.tcp.seq_num = base_seq
        w.send(packet, recalculate_checksum=True)

    set_ttl(packet, original_ttl)

# ──────────────────────────────────────────────────────────────────────────────
# Многосегментная фрагментация
# ──────────────────────────────────────────────────────────────────────────────

def pick_fragment_positions(payload_len: int, config: dict) -> list:
    """
    Вернуть отсортированный список уникальных точек разрыва внутри payload.
    Число фрагментов — случайное из [fragment_count_min, fragment_count_max],
    ограниченное длиной payload (нужен хотя бы 1 байт на фрагмент).
    """
    max_possible = max(1, payload_len - 1)

    if config["randomize_fragments"]:
        count = random.randint(config["fragment_count_min"], config["fragment_count_max"])
    else:
        count = config["fragment_count_min"]

    count = min(count, max_possible)
    if count < 2:
        return [payload_len // 2] if payload_len > 1 else []

    positions = sorted(random.sample(range(1, payload_len), count - 1))
    return positions


def split_payload(payload: bytes, positions: list) -> list:
    bounds  = [0, *positions, len(payload)]
    return [payload[bounds[i]:bounds[i + 1]] for i in range(len(bounds) - 1)]

# ──────────────────────────────────────────────────────────────────────────────
# Обработка TCP — фрагментация TLS ClientHello
# ──────────────────────────────────────────────────────────────────────────────

def process_tcp(packet, config: dict, w) -> None:
    """
    Перехватить TLS ClientHello для целевого домена и применить десинхронизацию.

    Режим 'fake_multisplit' (по умолчанию):
      1. Отправить fake_packet_count поддельных ClientHello с заниженным TTL
         (до реального сервера не доходят, но видны локальному DPI/ТСПУ).
      2. Разбить реальный payload на случайное число фрагментов со случайными
         точками разрыва и отправить их в перемешанном порядке.
      Современный ТСПУ буферизует и пересобирает поток перед анализом —
      простое разбиение на 2 части (см. legacy-режимы ниже) он это переживает.
      Фейковые пакеты засоряют трекинг DPI по потоку, а случайная
      многосегментность не даёт зафиксировать один и тот же паттерн разрыва.

    Режим 'multisplit':
      То же самое, но без фейковых пакетов.

    Режимы 'split' / 'disorder' (legacy, оставлены для отката):
      Разбиение ровно на 2 части в фиксированной позиции split_position.
    """
    payload = bytes(packet.payload) if packet.payload else b""

    if not is_tls_client_hello(payload) or not payload_matches_domains(
        payload, config["target_domains"]
    ):
        w.send(packet, recalculate_checksum=True)
        return

    with _stats_lock:
        _stats["intercepted"] += 1

    mode     = config["desync_mode"]
    base_seq = packet.tcp.seq_num

    if len(payload) <= max(2, config["fragment_count_min"]):
        w.send(packet, recalculate_checksum=True)
        return

    if config["fake_packet_enabled"] and mode in ("fake_multisplit", "multisplit", "split", "disorder"):
        send_fake_packets(packet, payload, base_seq, config, w)

    if mode in ("multisplit", "fake_multisplit"):
        positions = pick_fragment_positions(len(payload), config)
        chunks    = split_payload(payload, positions) if positions else [payload]

        offsets = [0]
        for c in chunks[:-1]:
            offsets.append(offsets[-1] + len(c))

        order = list(range(len(chunks)))
        if config["shuffle_fragment_order"] and len(order) > 1:
            random.shuffle(order)

        for i in order:
            packet.payload     = chunks[i]
            packet.tcp.seq_num = (base_seq + offsets[i]) & 0xFFFFFFFF
            w.send(packet, recalculate_checksum=True)

        log(
            f"{GREEN}[TCP FAKE+SPLIT]{RESET}  TLS ClientHello → "
            f"{YELLOW}{len(chunks)}{RESET} фрагм. (перемешан: "
            f"{YELLOW}{config['shuffle_fragment_order']}{RESET}), "
            f"фейков: {YELLOW}{config['fake_packet_count'] if config['fake_packet_enabled'] else 0}{RESET}"
        )

    else:
        pos   = min(config["split_position"], len(payload) - 1)
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
