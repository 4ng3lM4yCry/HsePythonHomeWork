import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os
import asyncio

# ==========================
#  Конфигурация
# ==========================
PCAP_FILE = "dhcp.pcapng"
TSHARK_PATH = r"C:\Users\rust0\Desktop\WiresharkPortable64\App\Wireshark\tshark.exe"  # <-- Укажите ваш путь
OUTPUT_CSV = "dns_requests.csv"
OUTPUT_JSON = "dns_requests.json"
PLOT_FILE = "dns_timeline.png"
UNIQUE_IPS_FILE = "unique_ips.txt"

# ==========================
#  Создание цикла событий asyncio
# ==========================
def ensure_event_loop():
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop

# ==========================
#  Чтение дампа и извлечение DNS-запросов
# ==========================
def extract_dns_requests(pcap_file, tshark_path=None):
    """
    Открывает pcap-файл, используя указанный путь к tshark (если задан),
    собирает DNS-запросы и все IP-адреса.
    """
    dns_records = []
    all_ips = set()

    print(f"[*] Открываем файл: {pcap_file}")
    # Передаём tshark_path, если он указан
    cap = pyshark.FileCapture(pcap_file, keep_packets=False, tshark_path=tshark_path)

    packet_count = 0
    try:
        for packet in cap:
            packet_count += 1
            if packet_count % 1000 == 0:
                print(f"   Обработано пакетов: {packet_count}")

            # Собираем IP-адреса
            if hasattr(packet, 'ip'):
                all_ips.add(packet.ip.src)
                all_ips.add(packet.ip.dst)
            elif hasattr(packet, 'ipv6'):
                all_ips.add(packet.ipv6.src)
                all_ips.add(packet.ipv6.dst)

            # DNS-запросы
            if hasattr(packet, 'dns'):
                dns_layer = packet.dns
                if hasattr(dns_layer, 'qry_name') and dns_layer.qry_name:
                    try:
                        timestamp = packet.sniff_time
                    except AttributeError:
                        timestamp = None

                    record = {
                        'time': timestamp,
                        'src_ip': packet.ip.src if hasattr(packet, 'ip') else None,
                        'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
                        'domain': dns_layer.qry_name,
                        'qry_type': dns_layer.get('qry_type', 'N/A')
                    }
                    dns_records.append(record)

    except Exception as e:
        print(f"[!] Ошибка при обработке пакетов: {e}")
    finally:
        cap.close()

    print(f"[+] Всего пакетов: {packet_count}")
    print(f"[+] Найдено DNS-запросов: {len(dns_records)}")
    print(f"[+] Уникальных IP-адресов: {len(all_ips)}")
    return dns_records, all_ips

# ==========================
#  Сохранение результатов
# ==========================
def save_results(dns_records, all_ips):
    if dns_records:
        df = pd.DataFrame(dns_records)
        df['time'] = df['time'].astype(str)
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"[+] DNS-запросы сохранены в {OUTPUT_CSV}")

        with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
            json.dump(dns_records, f, indent=2, default=str)
        print(f"[+] DNS-запросы сохранены в {OUTPUT_JSON}")

    if all_ips:
        with open(UNIQUE_IPS_FILE, 'w') as f:
            for ip in sorted(all_ips):
                f.write(ip + '\n')
        print(f"[+] Уникальные IP-адреса сохранены в {UNIQUE_IPS_FILE}")

# ==========================
#  Визуализация
# ==========================
def plot_dns_timeline(dns_records):
    if not dns_records:
        print("[!] Нет DNS-запросов для построения графика.")
        return

    df = pd.DataFrame(dns_records)
    df = df[df['time'].notna()].copy()
    if df.empty:
        print("[!] Нет временных меток для построения графика.")
        return

    df['time'] = pd.to_datetime(df['time'])
    df.set_index('time', inplace=True)
    df.sort_index(inplace=True)

    dns_per_minute = df.resample('1min').size()

    plt.figure(figsize=(12, 6))
    sns.set_style("whitegrid")
    plt.plot(dns_per_minute.index, dns_per_minute.values, marker='o', linestyle='-', color='b')
    plt.title('Количество DNS-запросов по времени', fontsize=16)
    plt.xlabel('Время', fontsize=12)
    plt.ylabel('Число запросов в минуту', fontsize=12)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(PLOT_FILE, dpi=150)
    plt.show()
    print(f"[+] График сохранён как {PLOT_FILE}")

# ==========================
#  Информация о доменах/IP
# ==========================
def print_suspicious_info(dns_records):
    if not dns_records:
        return
    df = pd.DataFrame(dns_records)
    print("\n[+] Уникальные домены в DNS-запросах:")
    unique_domains = df['domain'].unique()
    for domain in sorted(unique_domains)[:20]:
        print(f"    {domain}")
    if len(unique_domains) > 20:
        print(f"    ... и ещё {len(unique_domains)-20}")

    print("\n[+] Уникальные IP-адреса источников DNS-запросов:")
    unique_src = df['src_ip'].dropna().unique()
    for ip in sorted(unique_src)[:20]:
        print(f"    {ip}")
    if len(unique_src) > 20:
        print(f"    ... и ещё {len(unique_src)-20}")

# ==========================
#  Основная функция
# ==========================
def main():
    ensure_event_loop()

    if not os.path.exists(PCAP_FILE):
        print(f"[!] Файл {PCAP_FILE} не найден. Поместите дамп в ту же папку или укажите правильный путь.")
        return

    # Проверим, существует ли tshark по указанному пути
    if not os.path.exists(TSHARK_PATH):
        print(f"[!] tshark не найден по пути: {TSHARK_PATH}")
        print("[!] Укажите правильный путь в переменной TSHARK_PATH.")
        return

    dns_records, all_ips = extract_dns_requests(PCAP_FILE, tshark_path=TSHARK_PATH)

    save_results(dns_records, all_ips)
    plot_dns_timeline(dns_records)
    print_suspicious_info(dns_records)

    print("\n[*] Анализ завершён.")

if __name__ == "__main__":
    main()