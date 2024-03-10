#MSPR6.1-Harvester

Introduction
Le projet Harvester Network Scanner est un outil conçu pour faciliter l'analyse et la surveillance des réseaux informatiques. Ce scanner de réseau permet de détecter les appareils connectés, d'identifier les ports ouverts permettant de déduire et de prévenir d'éventuelles vulnérabilités. L'objectif est d'offrir une vision claire de l'état de sécurité d'un réseau pour permettre aux utilisateurs d'agir proactivement contre les risques potentiels.
Ce projet trouve son utilité dans divers contextes, allant de l'usage personnel pour sécuriser les réseaux domestiques, à l'application professionnelle pour les entreprises cherchant à protéger leurs infrastructures numériques. Il est également pertinent dans le domaine éducatif, où il peut servir d'outil pédagogique pour enseigner les fondamentaux de la sécurité réseau.
En somme, Harvester Network Scanner se positionne comme une solution pratique et accessible pour quiconque souhaite avoir une meilleure maîtrise de la connaissance de son réseau informatique afin de mieux le protéger. 
#Liens des repository : 
Nester : https://github.com/Julilaa/MSPR6.1-Nester 
Harvester : https://github.com/Julilaa/MSPR6.1-Harvester 

Fonctionnalités
Le projet Harvester Network Scanner est une solution complète dédiée à l'analyse et à la surveillance des réseaux informatiques. Il propose un ensemble de fonctionnalités avancées pour l'identification et l'évaluation des dispositifs connectés sur un réseau local. Voici un aperçu plus détaillé de ses principales fonctionnalités :
Identification des appareils sur le réseau : Harvester effectue une analyse approfondie pour détecter tous les appareils connectés au réseau, en recueillant des informations essentielles telles que les adresses IP et les adresses MAC, permettant ainsi une identification précise de chaque dispositif.
Analyse des ports ouverts : Le logiciel scanne les ports de chaque appareil détecté pour identifier les services actifs et les ports ouverts. Cette fonctionnalité est cruciale pour évaluer la sécurité du réseau et détecter d'éventuelles vulnérabilités.
Mesure de la latence (ping) : Harvester mesure le temps de réponse entre l'ordinateur hôte et les appareils connectés, fournissant des données précieuses sur la performance et la fiabilité du réseau.
Surveillance des ressources système : L'outil recueille des informations sur l'utilisation du processeur (CPU), de la mémoire, du disque de l'appareil analysé et le nombre de processus en cours sur la machine offrant une vision globale de l'état de fonctionnement et de sa performance.
Interface utilisateur intuitive : Harvester est équipé d'une interface graphique claire, facilitant l'exécution des scans, la visualisation des résultats et l'interaction avec le logiciel sans nécessiter de compétences techniques avancées.
Sauvegarde et historique des scans : Les informations recueillies lors des scans sont sauvegardées localement sous forme de fichiers JSON pour une analyse ultérieure ou pour tenir un historique des scans du réseau.
Mises à jour automatiques : Le système intègre une fonctionnalité de mise à jour automatique pour garantir que le logiciel reste à jour avec les derniers correctifs de sécurité et les nouvelles fonctionnalités.
En intégrant Git et GitHub pour la gestion des mises à jour, le Harvester Network Scanner assure une maintenance simplifiée et sécurisée. Grâce à ces outils, les utilisateurs bénéficient d'un accès immédiat aux dernières améliorations et correctifs, directement intégrés via des procédures de mise à jour automatisées. Cette stratégie permet non seulement de garantir la sécurité du logiciel en appliquant rapidement les patches de sécurité, mais aussi de proposer continuellement de nouvelles fonctionnalités et optimisations.
Ainsi, sur le plan technologique, le Harvester Network Scanner combine Python pour sa flexibilité et sa riche bibliothèque de modules, Flask pour la gestion efficace des interactions API, et nmap pour les capacités de scan réseau avancées. L'utilisation de Git et GitHub pour les mises à jour automatiques renforce la fiabilité et la réactivité du logiciel face aux évolutions technologiques et aux menaces de sécurité, offrant aux utilisateurs une solution robuste et évolutive pour la gestion et la sécurisation des réseaux informatiques.

Configuration requise
Le Harvester Network Scanner est conçu pour être polyvalent et compatible avec les principaux systèmes d'exploitation, à savoir Linux et Windows. Cette flexibilité permet aux utilisateurs d'intégrer le scanner dans divers environnements informatiques.
Sur Linux :
Mise à jour du système: Commencez par mettre à jour les paquets de votre distribution Linux pour vous assurer que tous les logiciels sont à jour. Utilisez la commande sudo apt-get update.
Installation de nmap: Le scanner réseau nmap est crucial pour le projet. Installez-le avec sudo apt-get install nmap et vérifiez son installation avec nmap --version.
Python 3: Le projet requiert Python 3.6 ou une version ultérieure. Vérifiez si Python 3 est déjà installé sur votre système avec python3 --version. Si nécessaire, installez-le via le gestionnaire de paquets de votre distribution.
Pip pour Python 3: Pip est le gestionnaire de paquets pour Python, utilisé pour installer des bibliothèques supplémentaires. Installez-le avec sudo apt install python3-pip si ce n'est pas déjà fait.
Bibliothèques Python nécessaires: Le projet dépend de plusieurs bibliothèques Python, dont Flask pour l'API, ainsi que d'autres modules pour le scanning et l'interface utilisateur. Installez-les en utilisant pip : pip3 install Flask python-nmap requests psutil.
Tkinter pour l'interface graphique: Tkinter est utilisé pour l'interface utilisateur du scanner. Installez-le via sudo apt install python3-tk.
Outils réseau: Pour certaines commandes réseau comme ifconfig, installez les outils réseau avec sudo apt install net-tools.
Configuration du pare-feu: Si un pare-feu est actif, assurez-vous d'ouvrir le port utilisé par l'API Flask, typiquement le 5000, avec une commande comme sudo ufw allow 5000/tcp.
Git pour les mises à jour: Pour bénéficier des mises à jour automatiques via GitHub, installez Git avec sudo apt install git.
Sur Windows :
Python 3: Téléchargez et installez Python depuis le site officiel, en veillant à cocher l'option pour ajouter Python et Pip au PATH.
nmap: Téléchargez et installez nmap depuis le site officiel de nmap.
Bibliothèques Python: Installez les bibliothèques nécessaires en ouvrant l'invite de commande ou PowerShell et en exécutant pip install Flask python-nmap requests psutil.
Tkinter: Inclus dans l'installation standard de Python sur Windows, Tkinter ne nécessite pas d'installation supplémentaire.
Git: Pour les mises à jour, téléchargez et installez Git pour Windows depuis son site officiel, en ajoutant également Git au PATH.

Dépendances externes :
Le projet peut requérir un accès à des services ou API externes, en particulier pour la mise à jour du logiciel via GitHub. Il faut s'assurer que la configuration réseau autorise l'accès à ces ressources externes et que les paramètres de proxy ou de pare-feu sont correctement configurés.
En suivant ces étapes, le système sera préparé à exécuter le Harvester Network Scanner et à tirer pleinement parti de ses fonctionnalités de surveillance et d'analyse réseau.

Installation et configuration
L'installation et la configuration du Harvester Network Scanner nécessitent plusieurs étapes essentielles pour garantir un fonctionnement optimal sur les systèmes Linux et Windows. Ce guide détaillé vous accompagnera à travers les processus d'installation des dépendances et de configuration de l'environnement.
Pour les utilisateurs Linux :
Mise à jour des paquets :
Avant de commencer, il est crucial de mettre à jour les paquets existants pour assurer la compatibilité et la sécurité. Ouvrez un terminal et exécutez la commande suivante :
sudo apt-get update
Installation de nmap :
Nmap est un outil indispensable pour le scan réseau. Pour l'installer, utilisez la commande :
sudo apt-get install nmap
Vous pouvez vérifier l'installation réussie avec `nmap --version`.
Installation de Python et Pip :
Le projet nécessite Python 3.6 ou ultérieur. La plupart des distributions Linux récentes incluent Python par défaut. Vérifiez votre version avec `python3 --version`. 
Pour installer Pip, l'outil de gestion des paquets Python, utilisez :
sudo apt install python3-pip
Installation des bibliothèques Python :
Plusieurs bibliothèques Python sont nécessaires pour le bon fonctionnement du scanner. Installez-les en exécutant :
pip3 install flask nmap python-tk requests psutil
Flask est utilisé pour l'API, python-tk pour l'interface utilisateur, et les autres bibliothèques pour diverses fonctionnalités du scanner.
Installation de Git :
Git est utilisé pour les mises à jour du logiciel. Pour l'installer, utilisez : 
sudo apt install git
Configuration du pare-feu :
Si vous utilisez un pare-feu, assurez-vous d'autoriser le trafic sur le port utilisé par l'API, généralement le port 5000 :
sudo ufw allow 5000/tcp
Pour les utilisateurs Windows :
Installation de Python :
Téléchargez et installez la dernière version de Python depuis le site officiel. Assurez-vous d'ajouter Python et Pip au PATH pendant l'installation.
Installation de nmap :
Téléchargez et installez nmap depuis le site officiel.
Installation des bibliothèques Python :
   Ouvrez l'invite de commande ou PowerShell et installez les bibliothèques nécessaires :
pip install flask nmap pytk requests psutil
Installation de Git :
Téléchargez et installez Git pour Windows depuis le site officiel. Assurez-vous également de l'ajouter au PATH.
Configuration de l'environnement :
Variables d'environnement :
Assurez-vous que les chemins vers Python, Pip, et Git (ainsi que le token discord pour les techniciens) sont correctement ajoutés à vos variables d'environnement pour permettre l'exécution des commandes depuis n'importe quel répertoire dans votre terminal ou invite de commande.


Suivez ces instructions pour préparer l'environnement à l'utilisation du Harvester Network Scanner. Une installation correcte et une configuration soignée sont cruciales pour tirer le meilleur parti des capacités de cet outil de scan réseau.
Utilisation
L'utilisation du Harvester Network Scanner est conçue pour être intuitive, offrant une interface claire qui guide les utilisateurs à travers les différentes fonctionnalités et options de scan réseau. Voici un guide étape par étape pour démarrer avec l'application et tirer parti de ses principales fonctionnalités.
Lancement de l'Application par ligne de commande :
Ouvrir le Terminal ou l'Invite de Commande :
Sur Linux, ouvrez votre terminal. Sur Windows, ouvrez l'invite de commande ou PowerShell.
Naviguer vers le Répertoire du Projet :
Utilisez la commande cd pour naviguer dans le dossier où vous avez enregistré le projet Harvester Network Scanner.
Exécuter l'Application :
Lancez l'application en exécutant le script Python principal. Si le fichier s'appelle ScanVFLinux.py ou ScanVFWindows.py, tapez :
python3 ScanVFLinux.py  # Pour Linux 
ou 
python ScanVFWindows.py  # Pour Windows
Lancement de l'application par l'exécution de l'exécutable :
Sur Windows ou Linux double-cliquez sur le fichier .exe que nous avons préparé.
Interface utilisateur :
Une fois l'application lancée, vous serez accueilli par une interface utilisateur graphique (GUI) simple et claire, qui présente les options de scan réseau disponibles.
Utilisation de l'Interface :
Scan Rapide (machine locale) :
Le scan rapide offre un aperçu immédiat de l'état de votre machine locale, incluant l'adresse IP, l'adresse MAC, les ports ouverts, la latence, l'utilisation du CPU, la mémoire, la batterie, le nombre de processus en cours et l'heure du scan.
Pour lancer cette opération, cliquez sur le bouton "Scan rapide (machine locale)" sur l'interface principale. Les résultats seront affichés directement dans l'interface utilisateur.
Scan Réseau Complet :
Pour une analyse plus approfondie, le scan réseau complet examine l'ensemble du réseau auquel votre machine est connectée, identifiant les appareils actifs, leurs adresses IP, adresses MAC, ports ouverts et l'heure du scan.
Cliquez sur "Lancer le scan réseau complet" pour démarrer cette opération. Selon la taille du réseau, cette opération peut prendre un certain temps.
Mise à Jour de l'Application :
Nous avons intégré une fonction de mise à jour automatique pour assurer que vous utilisez toujours la version la plus récente et sécurisée du logiciel.
Pour vérifier et appliquer les mises à jour, un bouton dédié est disponible dans l'interface. En cliquant sur ce bouton, le Harvester vérifiera les dernières modifications disponibles sur le dépôt GitHub. Si une mise à jour est détectée, une boîte de dialogue vous demandera si vous souhaitez l'appliquer. En confirmant, les dernières modifications seront téléchargées et intégrées à votre application sans interrompre son fonctionnement.

Interprétation des Résultats :
Résultats de Scan pour le Client :
Les résultats du scan s'afficheront dans une nouvelle fenêtre ou dans le terminal lui-même, listant les appareils détectés avec leurs adresses IP, noms d'hôte, adresses MAC, ports ouverts, et autres informations pertinentes comme la latence, l'utilisation du CPU, la mémoire, etc.
Analyse des Données :
Utilisez les informations fournies pour évaluer la sécurité de votre réseau. Les ports ouverts indiqués peuvent vous aider à identifier les services en cours d'exécution sur chaque appareil et à prendre des décisions éclairées concernant les éventuelles mesures de sécurité à adopter.
Nester : 
Nester est l'interface web conçue pour afficher et gérer les résultats collectés par le Harvester Network Scanner. Elle joue un rôle crucial en rendant les données complexes du scan réseau accessibles et compréhensibles pour les utilisateurs. Voici quelques points clés sur l'interprétation des résultats à travers Nester :
Vue d'Ensemble :
Interface Claire : Nester offre une interface utilisateur épurée et intuitive, permettant une navigation facile à travers les informations recueillies lors des scans.
Affichage des Résultats : Les résultats des scans sont présentés sous forme de tableaux détaillés, avec des informations sur les adresses IP, noms des machines, adresses MAC, ports ouverts, latence, et d'autres métriques importantes.
Filtrage et Recherche : Nester permet de filtrer les résultats, facilitant l'analyse des données dans des réseaux de grande taille.
Téléchargement des résultats : Il est possible de télécharger les résultats des scans du Nester en un fichier JSON.

Interprétation des Données :
Adresses IP et Noms des Machines : Identifient de manière unique les appareils sur le réseau, aidant à distinguer chaque machine.
Adresses MAC : Fournissent l'identifiant physique de la carte réseau de chaque appareil, utile pour des besoins d'audit ou de sécurité.
Ports Ouverts : Indiquent les services en cours d'exécution et accessibles sur les appareils, essentiels pour évaluer la surface d'attaque potentielle.
Latence : Donne une idée de la réactivité du réseau et de la performance de la connexion avec chaque machine.
Utilisation du CPU et de la Mémoire : Offrent des perspectives sur la charge de travail et l'état de santé des appareils scannés.
Disque Utilisé et Utilisateurs Connectés : Fournissent des informations sur l'utilisation du stockage et les sessions actives, importantes pour la gestion des ressources.
Gestion des Données :
Exportation des Données : Nester permet d'exporter les données des scans en format JSON, facilitant l'archivage ou l'analyse ultérieure dans d'autres outils.
Sécurité de l'Accès : L'accès aux résultats de scan via Nester est sécurisé, nécessitant une authentification pour garantir que seules les personnes autorisées puissent consulter les données sensibles.
En somme, Nester transforme les données techniques collectées par Harvester en informations compréhensibles et actionnables, permettant aux administrateurs réseau et aux professionnels de la sécurité d'optimiser la gestion et la sécurisation de leur infrastructure informatique.



Conseils d'Utilisation :
Fréquence des Scans :
Effectuez des scans réseau régulièrement pour surveiller les changements et les nouveaux appareils sur votre réseau.
Sécurité :
Soyez attentif aux ports ouverts inattendus ou aux appareils non reconnus qui pourraient indiquer une faille de sécurité ou une intrusion sur votre réseau.
Mises à Jour :
Vérifiez régulièrement les mises à jour du Harvester Network Scanner pour bénéficier des dernières fonctionnalités et améliorations de sécurité.


Architecture du projet
L'architecture du Harvester Network Scanner est conçue pour offrir une combinaison efficace et rapide, adaptée tant aux environnements Linux que Windows. Elle se divise en plusieurs composants clés, travaillant de concert pour fournir une expérience utilisateur fluide et des fonctionnalités scan réseau.
Composants Principaux :
Interface Utilisateur (UI) : L'interface utilisateur est construite en utilisant Tkinter, une bibliothèque Python standard pour la création d'interfaces graphiques. Elle permet aux utilisateurs de lancer facilement des scans, de visualiser les résultats en temps réel et d'accéder à diverses fonctionnalités du scanner.
Moteur de Scan (Scanner Engine) : Au cœur du système se trouve le moteur de scan, basé sur nmap, un outil de sécurité réseau reconnu pour ses capacités étendues de découverte de réseaux et d'audit de sécurité. Le moteur de scan est responsable de l'exécution des commandes de scan et de l'analyse des réponses des appareils réseau.
API Flask : Une API est mise en place à l'aide de Flask, un micro-framework Python léger et puissant. L'API sert d'intermédiaire entre l'interface utilisateur et le moteur de scan, facilitant la communication et le transfert de données. Elle permet également l'intégration avec d'autres systèmes ou applications.
Gestion des Données : Les résultats des scans sont sauvegardés sous forme de fichiers JSON dans un répertoire local. Cette approche simplifie la gestion des données et assure une portabilité et une accessibilité élevées. L'application offre également la possibilité d'envoyer les résultats à l'API pour un traitement en ligne.
Mise à jour et Maintenance : Le système intègre une fonctionnalité de mise à jour automatique via Git, permettant aux utilisateurs de rester à jour avec les dernières améliorations et corrections de bugs. 
Diagrammes d'Architecture :
Bien que ce document ne contienne pas de diagrammes d'architecture, on peut imaginer une structure en couches où l'interface utilisateur se situe au niveau supérieur, suivie par l'API Flask comme couche intermédiaire de communication, et le moteur de scan nmap comme fondement. Les fichiers JSON de résultats forment la couche de données, stockant les informations extraites lors des scans.


Mise à jour et maintenance
Mise à jour de l'application
Le Harvester Network Scanner est équipé d'un mécanisme de mise à jour intégré qui utilise Git pour synchroniser avec le dépôt GitHub du projet. Cette fonctionnalité permet aux utilisateurs de bénéficier des dernières améliorations et corrections de bugs sans effort manuel complexe. Pour mettre à jour l'application :
Lancement de la mise à jour : Utilisez le bouton "Vérifier les mises à jour" dans l'interface utilisateur du Harvester pour initier la vérification. L'application interroge alors le dépôt GitHub pour détecter toute nouvelle modification.
Application des mises à jour : Si une mise à jour est disponible, l'utilisateur est invité à confirmer son installation. Après confirmation, le système exécute les commandes Git nécessaires pour récupérer et appliquer les changements depuis le dépôt distant.
Gestion des conflits : En cas de modifications locales (par exemple, des configurations personnalisées ou des ajouts au code), l'application tente d'abord de les préserver en utilisant git stash. Après la mise à jour, l'utilisateur peut réappliquer ses modifications locales. En cas de conflits, une intervention manuelle pourrait être nécessaire.
Maintenance et dépannage
Pour assurer le bon fonctionnement du Harvester Network Scanner, il est conseillé de procéder régulièrement à des vérifications et à l'entretien de l'environnement d'exécution :
Vérifications régulières : Assurez-vous que toutes les dépendances sont à jour et que l'environnement d'exécution est correctement configuré.
Sauvegardes : Il est prudent de réaliser des sauvegardes régulières des configurations et des données générées par l'application, en particulier les résultats des scans stockés localement.
Surveillance des performances : Surveillez les performances de l'application et l'utilisation des ressources pour détecter et corriger d'éventuels problèmes.

Sécurité
Dans le cadre du projet Harvester Network Scanner, plusieurs mesures ont été mises en place pour assurer la sécurité de l'application et protéger les données recueillies lors des scans de réseau. Voici un aperçu des considérations de sécurité importantes et des conseils pour sécuriser l'installation et l'utilisation de l'application :
Considérations de sécurité importantes : 

Authentification : L'accès aux résultats des scans de réseau via l'interface web Nester nécessite une authentification. Cela garantit que seules les personnes autorisées peuvent accéder aux informations sensibles.

Gestion des Mises à Jour : Le processus de mise à jour automatique intégré permet de maintenir l'application à jour avec les derniers correctifs de sécurité, réduisant ainsi la vulnérabilité aux attaques externes.

Stockage des Données : Les résultats des scans sont stockés localement sous forme de fichiers JSON, minimisant ainsi le risque associé à la gestion d'une base de données externe.

Conseils pour sécuriser l'installation et l'utilisation :

Utiliser des Connexions Réseau Sécurisées : Veillez à utiliser des connexions réseau sécurisées (par exemple, VPN) lors de l'utilisation du scanner Harvester, en particulier lors de l'envoi des données à l'API.

Mettre à jour régulièrement : Activez les mises à jour automatiques ou vérifiez régulièrement les mises à jour disponibles pour le Harvester Network Scanner afin de bénéficier des dernières améliorations de sécurité.

Prudence avec les Données : Soyez prudent lors de la manipulation des fichiers de résultats des scans, car ils contiennent des informations potentiellement sensibles sur votre réseau. Assurez-vous que ces fichiers sont stockés et partagés de manière sécurisée.

Configurer correctement les Pare-feu et Antivirus : Assurez-vous que vos pare-feu et solutions antivirus sont correctement configurés pour permettre le fonctionnement du scanner Harvester sans compromettre la sécurité de votre système.

Sécuriser l'Accès à l'API et à l'Interface Web : Utilisez des mots de passe forts pour l'authentification et envisagez la mise en place de mesures de sécurité supplémentaires, telles que le filtrage d'adresses IP ou l'authentification multi-facteurs, pour l'accès à l'interface web Nester.
Axe d'amélioration
Pour continuer à développer et améliorer le projet Harvester Network Scanner, il existe plusieurs axes d'amélioration potentiels ainsi que des recommandations pour la contribution communautaire :
Sécurité des Données : Bien que le projet utilise des mesures de base pour protéger les données, l'intégration d'une couche de sécurité supplémentaire comme le chiffrement des données stockées et la sécurisation de la communication entre le scanner et l'API renforcerait la protection des informations sensibles.
Interface Utilisateur : Améliorer l'interface utilisateur de l'application web Nester pour offrir une expérience plus intuitive et des fonctionnalités supplémentaires, telles que des filtres avancés pour les résultats des scans ou des visualisations graphiques des données.
Compatibilité et Portabilité : Travailler sur une meilleure compatibilité entre différentes plateformes et la portabilité de l'application pour faciliter son déploiement dans divers environnements informatiques.
Intégration avec d'autres Outils : Permettre l'intégration du Harvester Network Scanner avec d'autres outils et plateformes de gestion de réseau et de sécurité pour offrir une solution plus complète.
Automatisation et Planification : Intégrer des fonctionnalités d'automatisation et de planification pour les scans de réseau, permettant aux utilisateurs de configurer des scans périodiques sans intervention manuelle.
Mise en place d'un système de logs : Implémenter un système de logs pour tracer les activités de scan et les interactions avec l'API, ce qui peut aider au dépannage et à l'audit de sécurité.
