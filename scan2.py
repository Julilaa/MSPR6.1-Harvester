import tkinter as tk
from tkinter import messagebox
import nmap
import socket

class HarvesterApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Harvester App")

        self.scan_button = tk.Button(self, text="Lancer le scan réseau", command=self.scan_network)
        self.scan_button.pack()

    def scan_network(self):
        nm = nmap.PortScanner()
        nm.scan(hosts='192.168.1.0/24', arguments='-sV')  # Scan détaillé pour obtenir les adresses MAC et les ports
        connected_hosts = []

        for host in nm.all_hosts():
            if nm[host]['status']['state'] == 'up':
                host_info = f"Adresse IP: {host}\n"
                try:
                    host_name = socket.gethostbyaddr(host)[0]
                    host_info += f"Nom de la machine: {host_name}\n"
                except socket.herror:
                    host_info += f"Nom de la machine: N/A\n"
                
                mac_addr = nm[host]['addresses'].get('mac', 'N/A')
                host_info += f"Adresse MAC: {mac_addr}\n"
                open_ports = [port for port in nm[host]['tcp'].keys() if nm[host]['tcp'][port]['state'] == 'open']
                host_info += f"Ports ouverts: {', '.join(map(str, open_ports))}"
                connected_hosts.append(host_info)
        
        if connected_hosts:
            tk.messagebox.showinfo("Machines connectées", "\n\n".join(connected_hosts))
        else:
            tk.messagebox.showinfo("Aucune machine connectée", "Aucune machine connectée trouvée.")

if __name__ == "__main__":
    app = HarvesterApp()
    app.mainloop()