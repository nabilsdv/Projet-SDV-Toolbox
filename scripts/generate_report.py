from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_pdf(report_text, filename="report.pdf"):
    """ Génère un rapport PDF à partir du scan Nmap """
    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, "🔍 Rapport de Scan Réseau")
    c.drawString(100, 730, report_text)
    c.save()
    print(f"📄 Rapport généré : {filename}")

if __name__ == "__main__":
    with open("nmap_results.txt", "r") as file:
        report_data = file.read()

    generate_pdf(report_data)
