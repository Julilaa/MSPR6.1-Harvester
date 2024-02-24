import tkinter as tk
from tkinter import messagebox
import nmap
import socket
import requests
import datetime 

class HarvesterApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Harvester App")

        self.scan_button = tk.Button(self, text="Lancer le scan réseau", command=self.scan_network)
        self.scan_button.pack()

    def scan_network(self):
        nm = nmap.PortScanner()
        nm.scan(hosts='172.20.10.0/24', arguments='-sV')
        connected_hosts = []
        
        # Obtenir l'heure actuelle et la formater en chaîne de caractères
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for host in nm.all_hosts():
            if nm[host]['status']['state'] == 'up':
                host_info = {
                    "Adresse IP": host,
                    "Nom de la machine": "N/A",
                    "Adresse MAC": nm[host]['addresses'].get('mac', 'N/A'),
                    "Ports ouverts": [],
                    "Heure du scan": scan_time 
                }
                try:
                    host_info["Nom de la machine"] = socket.gethostbyaddr(host)[0]
                except socket.herror:
                    pass

                open_ports = [port for port in nm[host]['tcp'].keys() if nm[host]['tcp'][port]['state'] == 'open']
                host_info["Ports ouverts"] = open_ports
                connected_hosts.append(host_info)

        # Envoyer chaque host_info à l'API via une requête POST
        url = 'http://localhost:5000/scan'  # URL de l'endpoint Flask
        for host_info in connected_hosts:
            response = requests.post(url, json=host_info)
            print(response.json())  # Afficher la réponse de l'API

        if connected_hosts:
            display_info = "\n\n".join([f"Adresse IP: {host['Adresse IP']}\nNom de la machine: {host['Nom de la machine']}\nAdresse MAC: {host['Adresse MAC']}\nPorts ouverts: {', '.join(map(str, host['Ports ouverts']))}\nHeure du scan: {host['Heure du scan']}" for host in connected_hosts])
            tk.messagebox.showinfo("Machines connectées", display_info)
        else:
            tk.messagebox.showinfo("Aucune machine connectée", "Aucune machine connectée trouvée.")

if __name__ == "__main__":
    app = HarvesterApp()
    app.mainloop()
