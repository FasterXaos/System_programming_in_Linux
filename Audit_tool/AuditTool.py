import psutil
import logging
import tkinter as tk
from tkinter import ttk
import time
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import datetime

logging.basicConfig(filename="system_audit.log", level=logging.INFO, format="%(asctime)s - %(message)s")

processes = {}
processStats = []
currentCanvas = None
isFirstRun = True

def monitorSystem():
    global isFirstRun

    while True:
        currentProcesses = {}
        statusCounts = {}

        for proc in psutil.process_iter(['pid', 'name', 'status']):
            try:
                currentProcesses[proc.info['pid']] = (proc.info['name'], proc.info['status'])
                status = proc.info['status']
                if status not in statusCounts:
                    statusCounts[status] = 0
                statusCounts[status] += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        if not isFirstRun:
            newProcesses = currentProcesses.keys() - processes.keys()
            terminatedProcesses = processes.keys() - currentProcesses.keys()

            for pid in newProcesses:
                processName = currentProcesses[pid][0]
                message = f"Process {processName} (PID: {pid}) started"
                processes[pid] = currentProcesses[pid]
                logMessage(message)

            for pid in terminatedProcesses:
                processName = processes[pid][0]
                message = f"Process {processName} (PID: {pid}) terminated"
                del processes[pid]
                logMessage(message)
        else:
            processes.update(currentProcesses)
            isFirstRun = False

        processStats.append({
            "timestamp": datetime.datetime.now(),
            "total": len(currentProcesses),
            **statusCounts
        })

        time.sleep(5)

def logMessage(message):
    logging.info(message)
    eventsListbox.insert(tk.END, message)
    eventsListbox.yview(tk.END)

def updateProcessList():
    processListbox.delete(0, tk.END)
    for pid, (name, status) in processes.items():
        processListbox.insert(tk.END, f"{name} (PID: {pid}, Status: {status})")
    processListbox.yview(tk.END)

def showReport():
    global currentCanvas
    if not processStats:
        return

    if currentCanvas:
        currentCanvas.get_tk_widget().destroy()

    for widget in statusFrame.winfo_children():
        widget.destroy()

    timestamps = [stat["timestamp"] for stat in processStats]
    totalCounts = [stat["total"] for stat in processStats]
    allStatuses = {key for stat in processStats for key in stat.keys() if key not in ("timestamp", "total")}

    fig, ax = plt.subplots(figsize=(8, 5))

    ax.plot(timestamps, totalCounts, label="Total Processes", color="blue")
    
    for status in allStatuses:
        counts = [stat.get(status, 0) for stat in processStats]
        ax.plot(timestamps, counts, label=status.capitalize())

    ax.set_xlabel("Time")
    ax.set_ylabel("Process Count")
    ax.set_title("Process Statistics Over Time")
    ax.legend()
    ax.grid(True)

    currentCanvas = FigureCanvasTkAgg(fig, master=reportFrame)
    currentCanvas.get_tk_widget().pack(side=tk.RIGHT, fill="both", expand=True)
    currentCanvas.draw()

    lastStat = processStats[-1]
    for status, count in lastStat.items():
        if status == "timestamp":
            continue
        statusLabel = tk.Label(statusFrame, text=f"{status.capitalize()}: {count}", font=("Arial", 10))
        statusLabel.pack(anchor="w")

root = tk.Tk()
root.title("System Audit Tool")

tabControl = ttk.Notebook(root)
tabProcess = ttk.Frame(tabControl)
tabReport = ttk.Frame(tabControl)

tabControl.add(tabProcess, text="Process Monitoring")
tabControl.add(tabReport, text="Generate Report")

tabControl.pack(expand=1, fill="both")

processFrame = tk.Frame(tabProcess)
processFrame.pack(fill="both", expand=True)

processListbox = tk.Listbox(processFrame, height=15, width=50)
processListbox.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)

processScroll = tk.Scrollbar(processFrame, command=processListbox.yview)
processListbox.config(yscrollcommand=processScroll.set)
processScroll.pack(side=tk.LEFT, fill=tk.Y)

eventsListbox = tk.Listbox(processFrame, height=15, width=50)
eventsListbox.pack(side=tk.RIGHT, padx=5, pady=5, fill=tk.BOTH, expand=True)

eventsScroll = tk.Scrollbar(processFrame, command=eventsListbox.yview)
eventsListbox.config(yscrollcommand=eventsScroll.set)
eventsScroll.pack(side=tk.RIGHT, fill=tk.Y)

updateButton = tk.Button(processFrame, text="Update Process List", command=updateProcessList)
updateButton.pack(pady=5)

reportFrame = tk.Frame(tabReport)
reportFrame.pack(fill="both", expand=True)

controlsFrame = tk.Frame(reportFrame)
controlsFrame.pack(side=tk.LEFT, fill="y", anchor="n", padx=10)

reportButton = tk.Button(controlsFrame, text="Show Report", command=showReport)
reportButton.pack(anchor="n", pady=5)

statusFrame = tk.Frame(controlsFrame)
statusFrame.pack(fill="x", anchor="n", pady=5)

monitorThread = threading.Thread(target=monitorSystem, daemon=True)
monitorThread.start()

root.mainloop()
