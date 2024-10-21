import os
import threading
from scapy.all import sniff, IP, TCP
import tkinter as tk
from tkinter import messagebox, Listbox, END


suspiciousIPs = []
blockedIPs = []
capturedPackets = []

MAX_PACKET_SIZE = 1000
SUSPICIOUS_PORTS = [22, 23, 80, 443]

sniffingActive = False


def isSuspicious(packet):
    if packet.haslayer(TCP):
        sourcePort = packet[TCP].sport
        destPort = packet[TCP].dport
        if len(packet) > MAX_PACKET_SIZE or sourcePort in SUSPICIOUS_PORTS or destPort in SUSPICIOUS_PORTS:
            return True
    return False

def packetCallback(packet):
    global capturedPackets
    capturedPackets.append(packet.summary())
    updatePacketList()
    
    if isSuspicious(packet):
        ipSource = packet[IP].src
        if ipSource not in suspiciousIPs:
            suspiciousIPs.append(ipSource)
            updateSuspiciousList()

def blockIP():
    try:
        selectedIP = suspiciousListbox.get(suspiciousListbox.curselection())
        if selectedIP:
            if selectedIP not in blockedIPs:
                blockedIPs.append(selectedIP)
                command = f"sudo iptables -A INPUT -s {selectedIP} -j DROP"
                os.system(command)
                updateBlockedList()
                messagebox.showinfo("IP Заблокирован", f"IP {selectedIP} был успешно заблокирован.")
            else:
                messagebox.showwarning("Ошибка", "IP уже заблокирован.")
    except:
        messagebox.showwarning("Ошибка", "Не выбран IP для блокировки.")

def unblockIP():
    try:
        selectedIP = blockedListbox.get(blockedListbox.curselection())
        if selectedIP:
            blockedIPs.remove(selectedIP)
            command = f"sudo iptables -D INPUT -s {selectedIP} -j DROP"
            os.system(command)
            updateBlockedList()
            messagebox.showinfo("IP Разблокирован", f"IP {selectedIP} был успешно разблокирован.")
    except:
        messagebox.showwarning("Ошибка", "Не выбран IP для разблокировки.")

def updatePacketList():
    yview = packetListbox.yview()
    packetListbox.delete(0, END)
    for packet in capturedPackets:
        packetListbox.insert(END, packet)
    if yview[1] == 1.0:
        packetListbox.see(END)

def updateSuspiciousList():
    yview = suspiciousListbox.yview()
    suspiciousListbox.delete(0, END)
    for ip in suspiciousIPs:
        suspiciousListbox.insert(END, ip)
    if yview[1] == 1.0:
        suspiciousListbox.see(END)

def updateBlockedList():
    yview = blockedListbox.yview()
    blockedListbox.delete(0, END)
    for ip in blockedIPs:
        blockedListbox.insert(END, ip)
    if yview[1] == 1.0:
        blockedListbox.see(END)

def sniffTraffic():
    sniff(iface="enp8s0", prn=packetCallback, store=False, stop_filter=lambda x: not sniffingActive)

def toggleSniffing():
    global sniffingActive
    if sniffingActive:
        sniffingActive = False
        startSniffButton.config(text="Запустить Sniffing")
    else:
        sniffingActive = True
        startSniffButton.config(text="Остановить Sniffing")
        sniffThread = threading.Thread(target=sniffTraffic)
        sniffThread.daemon = True
        sniffThread.start()


root = tk.Tk()
root.title("Мониторинг сетевого трафика")

root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_columnconfigure(2, weight=1)
root.grid_rowconfigure(0, weight=1)

leftFrame = tk.Frame(root)
leftFrame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

tk.Label(leftFrame, text="Все пакеты").pack()
packetListbox = Listbox(leftFrame, width=50, height=20)
packetListbox.pack(fill=tk.BOTH, expand=True)
startSniffButton = tk.Button(leftFrame, text="Запустить Sniffing", command=toggleSniffing)
startSniffButton.pack(pady=5)

middleFrame = tk.Frame(root)
middleFrame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

tk.Label(middleFrame, text="Подозрительные IP").pack()
suspiciousListbox = Listbox(middleFrame, width=30, height=20)
suspiciousListbox.pack(fill=tk.BOTH, expand=True)
blockButton = tk.Button(middleFrame, text="Заблокировать", command=blockIP)
blockButton.pack(pady=5)

rightFrame = tk.Frame(root)
rightFrame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")

tk.Label(rightFrame, text="Заблокированные IP").pack()
blockedListbox = Listbox(rightFrame, width=30, height=20)
blockedListbox.pack(fill=tk.BOTH, expand=True)
unblockButton = tk.Button(rightFrame, text="Разблокировать", command=unblockIP)
unblockButton.pack(pady=5)

root.mainloop()
