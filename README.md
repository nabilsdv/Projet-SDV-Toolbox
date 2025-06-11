# SDV Toolbox

## Présentation

**La SDV Toolbox** est une suite d'outils de sécurité offensive et défensive regroupés sous une interface centralisée.  
Elle permet d'accéder facilement à une large panoplie d'outils de pentest, d'analyse réseau, de tests d'intrusion applicatifs et d'audit d'infrastructure.

L'objectif de ce projet est de faciliter l'automatisation et l'orchestration de nombreux outils de sécurité tout en offrant une interface propre, ergonomique et pédagogique.

Version actuelle : **v2.1.0**

---

## Fonctionnalités principales

L'application regroupe les outils sous plusieurs catégories :

### 🔐 Sécurité (SOC, EDR, XDR)

- **Nmap** : Scanner de ports et découverte réseau avancée
- **Metasploit** : Framework de test de pénétration et d'exploitation
- **Wireshark** : Analyseur de protocoles réseau en temps réel
- **OWASP ZAP** : Scanner de vulnérabilités d’applications web

### 💻 Développement

- **Burp Suite** : Plateforme de test de sécurité des applications web
- **Postman** : Outil de test et développement d’API
- **SQLmap** : Détection et exploitation des injections SQL
- **OWASP** : Documentation et ressources de sécurité applicative

### 🏗 Infrastructure

- **SSL Check** : Analyse des certificats SSL/TLS
- **Wapiti** : Scanner de vulnérabilités applicatives web
- **Hydra** : Brute force réseau

### 🛠 Support Client & Assistance

- **Nikto** : Scanner de vulnérabilités de serveurs web
- **SSLyze** : Analyse de configuration SSL/TLS
- **Ettercap** : Attaques Man-In-The-Middle
- **TheHarvester** : Collecte d’informations OSINT

### 👥 RH & Administration

- **John The Ripper** : Craquage de mots de passe
- **Acunetix** : Scanner de vulnérabilités applicatives web
- **Nmap Scripting Engine (NSE)** : Scripts avancés Nmap

---

## Fonctionnalités additionnelles

- Interface Web moderne et responsive
- Authentification avec rôles utilisateur (Admin, Pentester, Analyst, Junior, Guest)
- Comptes de démonstration préconfigurés
- Statistiques d'utilisation en temps réel
- Architecture extensible pour ajout de nouveaux modules

---

## Accès de démonstration

| Rôle         | Identifiant | Mot de passe |
|--------------|-------------|---------------|
| Admin        | `admin`     | `admin123`    |
| Pentester    | `pentester` | `hack2024`    |
| Analyst      | `analyst`   | `security01`  |
| Junior       | `junior`    | `newbie456`   |
| Guest        | `guest`     | `guest789`    |

---

## Stack Technique

- **Python 3.11+**
- **Flask / Flask-SQLAlchemy**
- **SQLAlchemy + PyMySQL**
- **MySQL / MariaDB**
- **Front-end HTML/CSS/JS**
- **Interface graphique web full responsive**
- **Environnement testé sur Kali Linux**

---

## Installation

### Pré-requis

- Python 3.11+
- MySQL ou MariaDB
- Toutes les dépendances Python listées dans `requirements.txt`

### Clonage du projet

```bash
git clone https://github.com/nabilsdv/Projet-SDV-Toolbox.git
cd Projet-SDV-Toolbox
python3 webapp/app.py
