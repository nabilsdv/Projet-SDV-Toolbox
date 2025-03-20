def generate_report():
    """ Génère un rapport PDF à partir du dernier scan Nmap """
    try:
        import os
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas

        if not os.path.exists("nmap_results.txt"):
            text_output.insert(tk.END, "❌ Erreur : Aucun scan trouvé !\n")
            return

        with open("nmap_results.txt", "r") as file:
            report_data = file.read()

        c = canvas.Canvas("report.pdf", pagesize=letter)
        c.drawString(100, 750, "🔍 Rapport de Scan Réseau")
        c.drawString(100, 730, report_data[:500])  # Afficher une partie du scan
        c.save()
        text_output.insert(tk.END, "📄 Rapport généré : report.pdf\n")

    except ModuleNotFoundError:
        text_output.insert(tk.END, "⚠️ ReportLab n'est pas installé ! Installez-le avec 'pip install reportlab'\n")
    except Exception as e:
        text_output.insert(tk.END, f"❌ Une erreur s'est produite : {str(e)}\n")

