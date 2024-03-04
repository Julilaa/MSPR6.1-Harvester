import tkinter as tk
from tkinter import messagebox, ttk
import nmap
import socket
import requests
import datetime
import subprocess
import psutil

class HarvesterApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Windows Harvester Network Scanner")
        self.geometry("600x400")

        # Configuration des styles
        self.style = ttk.Style(self)
        self.style.configure('TButton', font=('Helvetica', 12), borderwidth='4')
        self.style.configure('TLabel', font=('Helvetica', 14), padding=10)

        # Mise en place de l'interface utilisateur
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        self.title_label = ttk.Label(self.main_frame, text="Network Scanner", style='TLabel')
        self.title_label.pack()

        self.info_label = ttk.Label(self.main_frame, text="Le scan peut durer quelques minutes, veuillez patienter...", style='TLabel')
        self.info_label.pack()

        # Bouton de scan rapide placé avant le scan complet
        self.quick_scan_button = ttk.Button(self.main_frame, text="Scan rapide (machine locale)", command=self.quick_scan, style='TButton')
        self.quick_scan_button.pack(pady=10)

        self.scan_button = ttk.Button(self.main_frame, text="Lancer le scan réseau complet", command=self.scan_network, style='TButton')
        self.scan_button.pack(pady=10)

    def ping_host(self, ip):
        """Effectue un ping sur l'hôte et renvoie la latence."""
        command = ['ping', '-n', '1', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            for line in output.splitlines():
                if "time=" in line:
                    latency = line.split('time=')[1].split()[0]
                    return latency
        except subprocess.CalledProcessError:
            return "N/A"
        return "N/A"

    def scan_network(self):
        nm = nmap.PortScanner()
        nm.scan(hosts='172.20.10.0/24', arguments='-sV')  # 10.60.121.0/24 # 172.20.10.0/24
        connected_hosts = []
        
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for host in nm.all_hosts():
            if nm[host]['status']['state'] == 'up':
                host_info = {
                    "Adresse IP": host,
                    "Nom de la machine": socket.getfqdn(host),
                    "Adresse MAC": nm[host]['addresses'].get('mac', 'N/A'),
                    "Ports ouverts": [port for port in nm[host]['tcp'].keys() if nm[host]['tcp'][port]['state'] == 'open'],
                    "Heure du scan": scan_time 
                }

                # Envoyer les informations à l'API
                response = requests.post('http://172.20.10.2:5000/scan', json=host_info)
                print(response.json())  # Afficher la réponse de l'API

                # Ajouter les informations dans la liste pour affichage
                connected_hosts.append(host_info)

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
                    latency = self.ping_host(host)  # Ping l'hôte pour obtenir la latence
                    host_name = socket.getfqdn(host)
                    mac_address = nm[host]['addresses'].get('mac', 'N/A')
                    open_ports = [port for port in nm[host]['tcp'].keys() if nm[host]['tcp'][port]['state'] == 'open']
                    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Collecte des informations supplémentaires avec psutil
                    cpu_usage = psutil.cpu_percent()
                    memory_usage = psutil.virtual_memory().percent
                    disk_usage = psutil.disk_usage('/').percent  # Changez le chemin si nécessaire
                    users = [user.name for user in psutil.users()]
                    battery_info = psutil.sensors_battery()
                    if battery_info:  # Vérifiez si battery_info n'est pas None
                        battery = battery_info.percent
                    else:
                        battery = "N/A"
                    process_count = len(psutil.pids())

                    host_info = {
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

                    # Envoyer les informations de la machine locale à l'API
                    try:
                        response = requests.post('http://172.20.10.2:5000/scan', json=host_info)
                        print(response.json())  # Afficher la réponse de l'API
                    except requests.exceptions.RequestException as e:  # Gérer toutes les exceptions pour les requêtes
                        print(f"Erreur lors de l'envoi des données à l'API: {e}")
                        messagebox.showinfo("Erreur", f"Impossible d'envoyer les données à l'API: {e}", parent=self)

                    info = (
                        f"Adresse IP: {host}\n"
                        f"Nom de l'hôte: {host_name}\n"
                        f"Adresse MAC: {mac_address}\n"
                        f"Ports ouverts: {', '.join(map(str, open_ports)) if open_ports else 'Aucun'}\n"
                        f"Latence: {latency} ms\n"
                        f"CPU utilisé: {cpu_usage}%\n"
                        f"Mémoire utilisée: {memory_usage}%\n"
                        f"Disque utilisé: {disk_usage}%\n"
                        f"Utilisateurs connectés: {', '.join(users)}\n"
                        f"Batterie: {battery}%\n"
                        f"Nombre de processus: {process_count}\n"
                    )
                    messagebox.showinfo("Informations de la machine locale", info, parent=self)
        else:
            messagebox.showinfo("Erreur", "Impossible de récupérer les informations de la machine locale.", parent=self)

if __name__ == "__main__":
    app = HarvesterApp()
    app.mainloop()
