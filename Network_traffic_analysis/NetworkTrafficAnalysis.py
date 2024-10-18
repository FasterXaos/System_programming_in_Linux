import tkinter as tk
from scapy.all import sniff, IP
import subprocess
import threading

# Глобальные переменные для хранения трафика, подозрительных и заблокированных IP
traffic_data = []
suspicious_data = []
blocked_ips = set()

# Функция для захвата трафика
def capture_traffic():
    def process_packet(packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            traffic_data.append(f"Source: {ip_src}, Destination: {ip_dst}")

            # Пример правила для фильтрации подозрительного трафика (например, IP с повторяющимися запросами)
            if suspicious_traffic_rule(packet):
                suspicious_data.append(f"Suspicious packet from {ip_src} to {ip_dst}")
        
        # Обновляем интерфейс после захвата пакета
        update_fields()

    # Ограничиваем захват 100 пакетами или устанавливаем тайм-аут 10 секунд
    sniff(prn=process_packet, store=False, count=10, timeout=10)

# Пример простого правила для обнаружения подозрительного трафика
def suspicious_traffic_rule(packet):
    # Простое правило: проверяем на многократные запросы от одного IP
    ip_src = packet[IP].src
    if len([p for p in traffic_data if ip_src in p]) > 10:  # Больше 10 запросов
        return True
    return False

# Функция для блокировки IP с использованием netsh (для Windows)
def block_ip(ip):
    blocked_ips.add(ip)
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"], check=True)
        print(f"IP {ip} успешно заблокирован")
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при блокировке IP: {e}")
    update_fields()

# Функция для разблокировки IP с использованием netsh (для Windows)
def unblock_ip(ip):
    blocked_ips.discard(ip)
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=Block_{ip}"], check=True)
        print(f"IP {ip} успешно разблокирован")
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при разблокировке IP: {e}")
    update_fields()

# Функция для обновления интерфейса
def update_fields():
    traffic_field.delete(1.0, tk.END)
    suspicious_field.delete(1.0, tk.END)
    blocked_field.delete(1.0, tk.END)

    traffic_field.insert(tk.END, "\n".join(traffic_data[-10:]))  # Показываем последние 10 пакетов
    suspicious_field.insert(tk.END, "\n".join(suspicious_data[-10:]))
    blocked_field.insert(tk.END, "\n".join(blocked_ips))

# Функция для блокировки подозрительного IP через интерфейс
def block_suspicious_ip():
    if suspicious_data:
        last_suspicious = suspicious_data[-1]
        ip_to_block = last_suspicious.split()[3]
        block_ip(ip_to_block)

# Функция для разблокировки последнего заблокированного IP
def unblock_last_ip():
    if blocked_ips:
        last_blocked = list(blocked_ips)[-1]
        unblock_ip(last_blocked)

# Функция для запуска захвата трафика в отдельном потоке
def start_capture_thread():
    capture_thread = threading.Thread(target=capture_traffic)
    capture_thread.daemon = True  # Поток завершится при закрытии программы
    capture_thread.start()

# Интерфейс с использованием Tkinter
root = tk.Tk()
root.title("Network Traffic Monitoring and Blocking")

# Поля для отображения трафика, подозрительных запросов и заблокированных IP
traffic_field = tk.Text(root, height=10, width=50)
traffic_field.grid(row=1, column=0)

suspicious_field = tk.Text(root, height=10, width=50)
suspicious_field.grid(row=1, column=1)

blocked_field = tk.Text(root, height=10, width=50)
blocked_field.grid(row=1, column=2)

# Кнопки для взаимодействия с трафиком
load_traffic_button = tk.Button(root, text="Capture Traffic", command=start_capture_thread)
load_traffic_button.grid(row=0, column=0)

block_button = tk.Button(root, text="Block Suspicious", command=block_suspicious_ip)
block_button.grid(row=0, column=1)

unblock_button = tk.Button(root, text="Unblock Last", command=unblock_last_ip)
unblock_button.grid(row=0, column=2)

root.mainloop()
