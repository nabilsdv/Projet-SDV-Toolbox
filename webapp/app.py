from flask import Flask, render_template, request
import subprocess

app = Flask(__name__, template_folder="templates")

# Page d'accueil
@app.route('/')
def home():
    return render_template("index.html", results=None)

# Route pour scanner l'IP avec Nmap
@app.route('/scan', methods=['GET'])
def scan():
    target = request.args.get('target')
    if not target:
        return render_template("index.html", results="❌ Veuillez entrer une IP valide.")

    try:
        result = subprocess.run(["nmap", "-sV", target], capture_output=True, text=True, check=True)
        return render_template("index.html", results=result.stdout)
    except Exception as e:
        return render_template("index.html", results=f"❌ Erreur : {str(e)}")

# Route pour scanner un site web avec Nikto
@app.route('/nikto', methods=['GET', 'POST'])
def nikto_scan():
    if request.method == 'POST':
        target = request.form['target']
        if not target:
            return render_template("nikto.html", results="❌ Veuillez entrer une URL valide.")

        try:
            result = subprocess.run(["nikto", "-h", target], capture_output=True, text=True, check=True)
            return render_template("nikto.html", results=result.stdout)
        except Exception as e:
            return render_template("nikto.html", results=f"❌ Erreur : {str(e)}")

    return render_template("nikto.html", results=None)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
