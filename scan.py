import nmap
import requests
import socket

# Obtenir l'adresse IP locale de la machine
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# Scanner les ports ouverts et récupérer les informations de base
def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')
    return nm[ip].all_protocols()
    

# Envoyer les données à une interface web
def post_data(data, url):
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, json=data, headers=headers)
    return response.text

# Adresse IP locale
ip = get_local_ip()
print(f"Adresse IP : {ip}")

# Nom de la machine
hostname = socket.gethostname()
print(f"Nom de la machine : {hostname}")

# Ports connectés
ports = scan_ports(ip)
print(f"Ports connectés : {ports}")

# Données à envoyer
data = {
    'ip': ip,
    'hostname': hostname,
    'ports': ports,
}

# URL de l'interface web (à remplacer)
url = 'http://votreinterfaceweb.com/post'

# Envoi des données
result = post_data(data, url)
print(result)


print(f"Réponse du serveur : {result}")