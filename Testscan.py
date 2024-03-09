import tkinter as tk
from tkinter import messagebox, ttk
import nmap
import socket
import datetime
import subprocess
import psutil
import os
import json
import requests

class HarvesterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Linux Harvester Network Scanner")
        self.geometry("600x400")

        self.style = ttk.Style(self)
        self.style.configure('TButton', font=('Helvetica', 12), borderwidth='4')
        self.style.configure('TLabel', font=('Helvetica', 14), padding=10)

        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        self.title_label = ttk.Label(self.main_frame, text="Network Scanner", style='TLabel')
        self.title_label.pack()

        self.info_label = ttk.Label(self.main_frame, text="Le scan peut durer quelques minutes, veuillez patienter...", style='TLabel')
        self.info_label.pack()

        self.quick_scan_button = ttk.Button(self.main_frame, text="Scan rapide (machine locale)", command=self.quick_scan, style='TButton')
        self.quick_scan_button.pack(pady=10)

        self.scan_button = ttk.Button(self.main_frame, text="Lancer le scan réseau complet", command=self.scan_network, style='TButton')
        self.scan_button.pack(pady=10)

    def ping_host(self, ip):
        command = ['ping', '-c', '1', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            for line in output.splitlines():
                if "time=" in line:
                    latency = line.split('time=')[1].split()[0]
                    return latency
        except subprocess.CalledProcessError:
            return "N/A"
        return "N/A"

    def save_scan_results(self, host_info):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"scan_result_{timestamp}.json"
        data_folder = 'scan_data'
        if not os.path.exists(data_folder):
            os.makedirs(data_folder)
        file_path = os.path.join(data_folder, filename)
        with open(file_path, 'w') as file:
            json.dump(host_info, file, indent=4)
        messagebox.showinfo("Scan sauvegardé", f"Les résultats du scan ont été sauvegardés dans {file_path}.")

    def send_results_to_api(self, host_info):
        url = 'http://127.0.0.1:5000/upload'
        files = {'file': json.dumps(host_info)}
        try:
            response = requests.post(url, files=files)
            print("Data sent to API successfully:", response.text)
        except requests.exceptions.RequestException as e:
            print("Failed to send data to API:", e)
            messagebox.showerror("Error", f"Failed to send data to API: {e}")

    def scan_network(self):
        nm = nmap.PortScanner()
        nm.scan(hosts='172.10.20.0/24', arguments='-sV') #172.10.20.0/24 127.0.0.0/24
        connected_hosts = []
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for host in nm.all_hosts():
            if nm[host]['status']['state'] == 'up':
                host_info = {
                    "Adresse IP": host,
                    "Nom de la machine": socket.getfqdn(host),
                    "Adresse MAC": nm[host]['addresses'].get('mac', 'N/A'),
                    "Ports ouverts": [port for port in nm[host].get('tcp', {}).keys() if nm[host]['tcp'][port]['state'] == 'open'],
                    "Heure du scan": scan_time 
                }
                connected_hosts.append(host_info)
        self.save_scan_results(connected_hosts)
        if connected_hosts:
            display_info = "\n\n".join([f"Adresse IP: {host['Adresse IP']}\nNom de la machine: {host['Nom de la machine']}\nAdresse MAC: {host['Adresse MAC']}\nPorts ouverts: {', '.join(map(str, host['Ports ouverts']))}\nHeure du scan: {host['Heure du scan']}" for host in connected_hosts])
            messagebox.showinfo("Machines connectées", display_info, parent=self)
        else:
            messagebox.showinfo("Aucune machine connectée", "Aucune machine connectée trouvée.", parent=self)

    def quick_scan(self):
        local_ip = socket.gethostbyname(socket.gethostname())
        nm = nmap.PortScanner()
        nm.scan(hosts=local_ip, arguments='-sV')
        if nm.all_hosts():
            for host in nm.all_hosts():
                if nm[host]['status']['state'] == 'up':
                    host_info = self.collect_host_info(host, nm)
                    self.save_scan_results([host_info])
                    self.display_host_info(host_info)
        else:
            messagebox.showinfo("Erreur", "Impossible de récupérer les informations de la machine locale.", parent=self)

    def collect_host_info(self, host, scanner):
        latency = self.ping_host(host)
        host_name = socket.getfqdn(host)
        mac_address = scanner[host]['addresses'].get('mac', 'N/A')
        open_ports = [port for port in scanner[host].get('tcp', {}).keys() if scanner[host]['tcp'][port]['state'] == 'open']
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/').percent
        users = [user.name for user in psutil.users()]
        battery_info = psutil.sensors_battery()
        battery = battery_info.percent if battery_info else "N/A"
        process_count = len(psutil.pids())
        return {
            "Adresse IP": host,
            "Nom de la machine": host_name,
            "Adresse MAC": mac_address,
            "Ports ouverts": open_ports,
            "Latence": latency,
            "Heure du scan": scan_time,
            "CPU utilisé (%)": cpu_usage,
            "Mémoire utilisée (%)": memory_usage,
            "Disque utilisé (%)": disk_usage,
            "Utilisateurs connectés": users,
            "Batterie (%)": battery,
            "Nombre de processus": process_count
        }

    def display_host_info(self, host_info):
        info = (
            f"Adresse IP: {host_info['Adresse IP']}\n"
            f"Nom de l'hôte: {host_info['Nom de la machine']}\n"
            f"Adresse MAC: {host_info['Adresse MAC']}\n"
            f"Ports ouverts: {', '.join(map(str, host_info['Ports ouverts'])) if host_info['Ports ouverts'] else 'Aucun'}\n"
            f"Latence: {host_info['Latence']} ms\n"
            f"CPU utilisé: {host_info['CPU utilisé (%)']}%\n"
            f"Mémoire utilisée: {host_info['Mémoire utilisée (%)']}%\n"
            f"Disque utilisé: {host_info['Disque utilisé (%)']}%\n"
            f"Utilisateurs connectés: {', '.join(host_info['Utilisateurs connectés'])}\n"
            f"Batterie: {host_info['Batterie (%)']}%\n"
            f"Nombre de processus: {host_info['Nombre de processus']}\n"
        )
        messagebox.showinfo("Informations de la machine locale", info, parent=self)

if __name__ == "__main__":
    app = HarvesterApp()
    app.mainloop()
