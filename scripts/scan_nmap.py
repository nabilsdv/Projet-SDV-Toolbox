import subprocess
import sys

def scan_nmap(target):
    """ Exécute un scan Nmap et affiche les résultats """
    print(f"🔍 Scanning {target} with Nmap...")

    try:
        result = subprocess.run(["nmap", "-sV", target], capture_output=True, text=True, check=True)
        if result.stdout:
            with open("nmap_results.txt", "w") as file:
                file.write(result.stdout)
            print("✅ Scan terminé. Résultats sauvegardés dans nmap_results.txt")
        else:
            print("⚠️ Aucune donnée reçue de Nmap. Vérifie l'IP cible.")
    except FileNotFoundError:
        print("❌ Erreur : Nmap n'est pas installé. Installe-le avec 'sudo apt install nmap'")
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors de l'exécution de Nmap :\n{e.stderr}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_nmap.py <IP cible>")
        sys.exit(1)

    target_ip = sys.argv[1]
    scan_nmap(target_ip)
