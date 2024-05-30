import tkinter as tk
from tkinter import messagebox, ttk
import nmap
import socket
import requests
import datetime
import subprocess
import psutil
import json
import os

# Définition de la classe principale de l'application, qui hérite de tk.Tk.
class HarvesterApp(tk.Tk):
    def __init__(self):
        super().__init__()  # Initialisation de la classe parente tk.Tk.

        # Configuration de la fenêtre principale de l'application.
        self.title("Windows Harvester Network Scanner")
        self.geometry("600x400")

        # Configuration des styles pour les widgets de l'interface utilisateur.
        self.style = ttk.Style(self)
        self.style.configure('TButton', font=('Helvetica', 12), borderwidth='4')
        self.style.configure('TLabel', font=('Helvetica', 14), padding=10)

        # Création et configuration du cadre principal de l'interface utilisateur.
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        # Ajout des widgets à l'interface : titre, label d'information, boutons pour les différentes actions.
        self.title_label = ttk.Label(self.main_frame, text="Network Scanner", style='TLabel')
        self.title_label.pack()

        self.info_label = ttk.Label(self.main_frame, text="Le scan peut durer quelques minutes, veuillez patienter...", style='TLabel')
        self.info_label.pack()

        # Bouton pour effectuer un scan rapide de la machine locale.
        self.quick_scan_button = ttk.Button(self.main_frame, text="Scan rapide (machine locale)", command=self.quick_scan, style='TButton')
        self.quick_scan_button.pack(pady=10)

        # Bouton pour lancer un scan complet du réseau.
        self.scan_button = ttk.Button(self.main_frame, text="Lancer le scan réseau complet", command=self.scan_network, style='TButton')
        self.scan_button.pack(pady=10)

        # Bouton pour vérifier les mises à jour de l'application.
        self.update_button = ttk.Button(self.main_frame, text="Vérifier les mises à jour", command=self.check_for_updates, style='TButton')
        self.update_button.pack(pady=10)

        # Récupération du token GitHub depuis les variables d'environnement pour les mises à jour.
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.last_sha = None  # Dernier commit SHA connu pour vérifier les mises à jour.

    # Fonction pour vérifier les mises à jour sur GitHub.
    def check_for_updates(self):
        try:
            github_repo = "Julilaa/MSPR6.1-Harvester"  # Définition du dépôt GitHub.
            current_sha = self.check_for_updates_on_github(github_repo)  # Vérification du dernier commit.
            # Mise à jour de l'application si une nouvelle version est détectée.
            if current_sha and current_sha != self.last_sha:
                self.update_application(current_sha)
            else:
                # Information à l'utilisateur que l'application est à jour si aucun nouveau commit n'est trouvé.
                messagebox.showinfo("À jour", "Votre application est déjà à jour.")
        except Exception as e:
            # Affichage d'une erreur en cas de problème lors de la vérification des mises à jour.
            messagebox.showerror("Erreur", f"Impossible de vérifier les mises à jour : {e}")

    # Fonction pour récupérer le dernier commit SHA du dépôt GitHub.
    def check_for_updates_on_github(self, github_repo):
        api_url = f"https://api.github.com/repos/{github_repo}/commits?per_page=1"  # URL de l'API GitHub.
        headers = {'Authorization': f'token {self.github_token}'} if self.github_token else {}  # Authentification.
        response = requests.get(api_url, headers=headers)  # Requête GET vers l'API GitHub.
        if response.status_code == 200:
            commits = response.json()  # Parse la réponse JSON.
            if commits and isinstance(commits, list) and len(commits) > 0:
                last_commit_sha = commits[0]['sha']  # Récupère le SHA du dernier commit.
                return last_commit_sha
        return None

    # Fonction pour mettre à jour l'application en utilisant git.
    def update_application(self, current_sha):
        # Confirmation de la mise à jour par l'utilisateur.
        if messagebox.askyesno("Mise à jour disponible", "Des modifications ont été détectées. Voulez-vous mettre à jour ?"):
            try:
                self.pull_changes()  # Exécution des commandes git pour mettre à jour.
                messagebox.showinfo("Mise à jour", "L'application a été mise à jour.")
                self.last_sha = current_sha  # Mise à jour du SHA du dernier commit connu.
            except subprocess.CalledProcessError as e:
                # Affichage d'une erreur en cas d'échec de la mise à jour.
                messagebox.showerror("Erreur", f"Échec de la mise à jour : {e}")

    def pull_changes(self):
        try:
            # Exclure temporairement le dossier scan_results des suivis de Git pour éviter de conflit avec les modifications locales.
            subprocess.run(["git", "update-index", "--assume-unchanged", "scan_results/*"], check=True)
            
            # Sauvegarder les modifications locales et mettre à jour le répertoire de travail avec les dernières modifications du dépôt distant.
            subprocess.run(["git", "stash", "push"], check=True)
            subprocess.run(["git", "pull"], check=True)
            
            # Rétablir le suivi des modifications dans le dossier scan_results.
            subprocess.run(["git", "update-index", "--no-assume-unchanged", "scan_results/*"], check=True)
            
        except subprocess.CalledProcessError as e:
            # Gérer les erreurs potentielles pendant la mise à jour, telles que des conflits.
            messagebox.showerror("Erreur de mise à jour", f"Un problème est survenu lors de la mise à jour : {e}")
            
            # S'assurer que le dossier scan_results est de nouveau suivi par Git, même en cas d'erreur.
            subprocess.run(["git", "update-index", "--no-assume-unchanged", "scan_results/*"], check=True)
            
            # Informer l'utilisateur en cas de modifications locales sauvegardées qui nécessitent une gestion manuelle.
            if "stash" in str(e):
                messagebox.showinfo("Mise à jour - Gestion des modifications enregistrées",
                                    "Des modifications ont été enregistrées. Veuillez les gérer manuellement.")

    def ping_host(self, ip):
        """Fonction pour effectuer un ping sur une adresse IP donnée et mesurer la latence."""
        command = ['ping', '-n', '1', ip]
        try:
            # Exécution de la commande ping et récupération de la sortie.
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            for line in output.splitlines():
                if "time=" in line:
                    # Extraction et retour de la valeur de latence si trouvée.
                    latency = line.split('time=')[1].split()[0]
                    return latency
        except subprocess.CalledProcessError:
            # Retourner "N/A" si le ping échoue.
            return "N/A"
        return "N/A"

    def scan_network(self):
        # Initialisation de l'objet PortScanner de nmap pour le balayage réseau.
        nm = nmap.PortScanner()
        
        # Lancement d'un scan sur une plage d'adresses IP spécifique avec l'option -sV pour détecter les versions de services.
        nm.scan(hosts='172.20.10.0/24', arguments='-sV')
        
        # Liste pour stocker les informations des hôtes connectés.
        connected_hosts = []
        
        # Enregistrement du moment du scan.
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Itération sur chaque hôte détecté par le scan.
        for host in nm.all_hosts():
            if nm[host]['status']['state'] == 'up':
                # Compilation des informations de chaque hôte dans un dictionnaire.
                host_info = {
                    "Adresse IP": host,
                    "Nom de la machine": socket.getfqdn(host),
                    "Adresse MAC": nm[host]['addresses'].get('mac', 'N/A'),
                    "Ports ouverts": [port for port in nm[host]['tcp'].keys() if nm[host]['tcp'][port]['state'] == 'open'],
                    "Heure du scan": scan_time 
                }

                # Sauvegarde locale des informations de l'hôte.
                self.save_data_locally(host_info)

                try:
                    # Tentative d'envoi des informations de l'hôte à l'API via une requête POST.
                    response = requests.post('http://127.0.0.1:5000/scan', json=host_info)
                    # Affichage de la réponse de l'API dans la console.
                    print(response.json())
                except requests.exceptions.ConnectionError as e:
                    # Gestion des erreurs de connexion à l'API.
                    print(f"Impossible de se connecter à l'API sur la machine Windows. Erreur : {e}")
                # Ajout des informations de l'hôte à la liste des hôtes connectés.
                connected_hosts.append(host_info)

        if connected_hosts:
            # Compilation et affichage des informations de tous les hôtes connectés si la liste n'est pas vide.
            display_info = "\n\n".join([f"Adresse IP: {host['Adresse IP']}\nNom de la machine: {host['Nom de la machine']}\nAdresse MAC: {host['Adresse MAC']}\nPorts ouverts: {', '.join(map(str, host['Ports ouverts']))}\nHeure du scan: {host['Heure du scan']}" for host in connected_hosts])
            messagebox.showinfo("Machines connectées", display_info, parent=self)
        else:
            # Affichage d'un message indiquant qu'aucune machine connectée n'a été trouvée si la liste est vide.
            messagebox.showinfo("Aucune machine connectée", "Aucune machine connectée trouvée.", parent=self)

    def quick_scan(self):
        # Obtention de l'adresse IP locale de la machine pour le scan rapide.
        local_ip = socket.gethostbyname(socket.gethostname())
        nm = nmap.PortScanner()
        # Scan de l'adresse IP locale avec nmap pour détecter les services et ports ouverts.
        nm.scan(hosts=local_ip, arguments='-sV')

        if nm.all_hosts():
            # Traitement de chaque hôte détecté lors du scan.
            for host in nm.all_hosts():
                if nm[host]['status']['state'] == 'up':
                    # Mesure de la latence avec la fonction ping_host.
                    latency = self.ping_host(host)
                    # Récupération des informations supplémentaires sur l'hôte.
                    host_name = socket.getfqdn(host)
                    mac_address = nm[host]['addresses'].get('mac', 'N/A')
                    open_ports = [port for port in nm[host]['tcp'].keys() if nm[host]['tcp'][port]['state'] == 'open']
                    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Utilisation de psutil pour obtenir des informations détaillées sur la machine locale.
                    cpu_usage = psutil.cpu_percent()
                    memory_usage = psutil.virtual_memory().percent
                    disk_usage = psutil.disk_usage('/').percent
                    users = [user.name for user in psutil.users()]
                    battery_info = psutil.sensors_battery()
                    battery = battery_info.percent if battery_info else "N/A"
                    process_count = len(psutil.pids())

                    # Compilation des informations collectées en un dictionnaire.
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

                    # Sauvegarde locale des informations collectées.
                    self.save_data_locally(host_info)

                    try:
                        # Envoi des informations collectées à l'API pour traitement et affichage.
                        response = requests.post('http://172.168.200.2:5000/scan', json=host_info)
                        print(response.json())  # Affichage de la réponse de l'API.
                    except requests.exceptions.RequestException as e:
                        # Gestion des erreurs de communication avec l'API.
                        print(f"Erreur lors de l'envoi des données à l'API: {e}")
                        messagebox.showinfo("Erreur", f"Impossible d'envoyer les données à l'API: {e}", parent=self)

                    # Affichage des informations collectées dans une fenêtre d'information.
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
            # Affichage d'un message d'erreur si aucun hôte n'a été détecté lors du scan rapide.
            messagebox.showinfo("Erreur", "Impossible de récupérer les informations de la machine locale.", parent=self)

    def save_data_locally(self, data):
        """Sauvegarde les données scannées dans un fichier JSON en local."""
        # Création du nom de fichier basé sur la date et l'heure actuelles.
        filename = f"scan_result_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
        # Chemin du fichier dans le dossier scan_results.
        filepath = os.path.join('scan_results', filename)

        # Création du dossier si nécessaire.
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # Écriture des données dans le fichier JSON.
        with open(filepath, 'w') as file:
            json.dump(data, file, indent=4)

        # Confirmation de la sauvegarde des données.
        print(f"Les données ont été sauvegardées localement dans {filepath}.")

if __name__ == "__main__":
    app = HarvesterApp()
    app.mainloop()
