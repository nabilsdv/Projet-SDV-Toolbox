from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import os

class PDFReportGenerator:
    def __init__(self):
        self.reports_dir = "static/reports"
        os.makedirs(self.reports_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_styles()
    
    def _setup_styles(self):
        """Styles personnalisés SDV"""
        self.styles.add(ParagraphStyle(
            name='SDVTitle',
            parent=self.styles['Title'],
            fontSize=20,
            spaceAfter=20,
            textColor=colors.HexColor('#007bff'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='SDVHeader',
            parent=self.styles['Heading1'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.HexColor('#333333'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Courier',
            backgroundColor=colors.HexColor('#f8f9fa'),
            leftIndent=10,
            rightIndent=10,
            spaceAfter=10
        ))

        # NOUVEAU : Styles pour les nouveaux rapports
        self.styles.add(ParagraphStyle(
            name='section_title',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor('#333333'),
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='normal',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6
        ))

        self.styles.add(ParagraphStyle(
            name='code',
            parent=self.styles['Normal'],
            fontSize=8,
            fontName='Courier',
            backgroundColor=colors.HexColor('#f8f9fa'),
            leftIndent=10,
            rightIndent=10,
            spaceAfter=8
        ))
    
    def get_colored_style(self, color, bold=False, size=10):
        """Helper pour créer des styles colorés"""
        font_name = 'Helvetica-Bold' if bold else 'Helvetica'
        return ParagraphStyle(
            name=f'colored_{color}',
            parent=self.styles['Normal'],
            fontSize=size,
            textColor=colors.HexColor(color),
            fontName=font_name
        )

    def _create_header(self, tool_name, target=None):
        """En-tête commun - retourne une liste d'éléments"""
        story = []
        title = Paragraph("🛡 SDV Toolbox - Rapport de Sécurité", self.styles['SDVTitle'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Info scan
        info_data = [
            ['Outil:', tool_name],
            ['Date:', datetime.now().strftime('%d/%m/%Y à %H:%M:%S')],
            ['Cible:', target or 'N/A'],
            ['Opérateur:', 'SDV Security Team']
        ]
        
        info_table = Table(info_data, colWidths=[1.5*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        story.append(info_table)
        story.append(Spacer(1, 30))
        return story

    def _create_header_old(self, story, tool_name, target=None):
        """En-tête commun - VERSION POUR COMPATIBILITY"""
        title = Paragraph("🛡 SDV Toolbox - Rapport de Sécurité", self.styles['SDVTitle'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Info scan
        info_data = [
            ['Outil:', tool_name],
            ['Date:', datetime.now().strftime('%d/%m/%Y à %H:%M:%S')],
            ['Cible:', target or 'N/A'],
            ['Opérateur:', 'SDV Security Team']
        ]
        
        info_table = Table(info_data, colWidths=[1.5*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        story.append(info_table)
        story.append(Spacer(1, 30))

    def generate_hydra_report(self, results, target_info):
        """Rapport spécialisé pour Hydra avec mise en forme améliorée"""
        filename = f"hydra_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("Hydra", target_info))
        
        # Titre section
        story.append(Paragraph("■ Résultats de l'attaque Hydra", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Parser les résultats Hydra
        if "SUCCÈS" in results and "Identifiants trouvés" in results:
            # Succès - extraire les identifiants
            story.append(Paragraph("🎉 ATTAQUE RÉUSSIE", self.get_colored_style('#28a745', bold=True, size=14)))
            story.append(Spacer(1, 10))
            
            # Extraire login:password des résultats
            import re
            credentials = re.findall(r'login:\s*(\S+)\s+password:\s*(\S+)', results)
            
            if credentials:
                cred_data = [['Login', 'Mot de passe']]
                for login, password in credentials:
                    cred_data.append([login, password])
                
                cred_table = Table(cred_data, colWidths=[200, 200])
                cred_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(cred_table)
                story.append(Spacer(1, 15))
        
        elif "Service" in results and "fermé" in results:
            # Service fermé
            story.append(Paragraph("⚠ SERVICE INACCESSIBLE", self.get_colored_style('#ffc107', bold=True, size=14)))
            story.append(Spacer(1, 10))
            story.append(Paragraph("Le service cible n'est pas accessible ou est protégé par un firewall.", self.styles['normal']))
            story.append(Spacer(1, 10))
        
        elif "Aucun mot de passe trouvé" in results:
            # Aucun résultat
            story.append(Paragraph("❌ AUCUN RÉSULTAT", self.get_colored_style('#dc3545', bold=True, size=14)))
            story.append(Spacer(1, 10))
            story.append(Paragraph("Aucun mot de passe trouvé dans la wordlist.", self.styles['normal']))
            story.append(Spacer(1, 10))
        
        # Détails techniques
        story.append(Paragraph("Détails de l'attaque :", self.get_colored_style('#007bff', bold=True)))
        story.append(Spacer(1, 5))
        
        # Extraire les informations de configuration
        lines = results.split('\n')
        config_data = [['Paramètre', 'Valeur']]
        
        for line in lines:
            if 'max' in line and 'tasks' in line:
                import re
                tasks = re.search(r'max (\d+) tasks', line)
                if tasks:
                    config_data.append(['Tâches simultanées', tasks.group(1)])
            elif 'login tries' in line:
                tries = re.search(r'(\d+) login tries', line)
                if tries:
                    config_data.append(['Tentatives de connexion', tries.group(1)])
        
        if len(config_data) > 1:
            config_table = Table(config_data, colWidths=[200, 200])
            config_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(config_table)
            story.append(Spacer(1, 15))
        
        # Log complet (tronqué)
        story.append(Paragraph("Log détaillé :", self.get_colored_style('#6c757d', bold=True)))
        story.append(Spacer(1, 5))
        
        import re
        clean_results = re.sub(r'\*\*[^*]*\*\*', '', results)  # Supprimer les marqueurs markdown
        truncated_results = clean_results[:1000] + "..." if len(clean_results) > 1000 else clean_results
        story.append(Paragraph(truncated_results.replace('\n', '<br/>'), self.styles['code']))
        
        # Recommandations
        story.append(Spacer(1, 20))
        story.append(Paragraph("Recommandations de sécurité :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 5))
        
        recommendations = [
            "• Utilisez des mots de passe complexes et uniques",
            "• Implémentez une authentification à deux facteurs (2FA)",
            "• Limitez les tentatives de connexion (rate limiting)",
            "• Surveillez les logs d'authentification",
            "• Utilisez des clés SSH au lieu des mots de passe quand possible"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['normal']))
        
        doc.build(story)
        return filename

    def generate_john_report(self, results, hash_info, cracked=False):
        """Rapport spécialisé pour John the Ripper avec mise en forme améliorée"""
        filename = f"john_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("John the Ripper", hash_info))
        
        # Titre section
        story.append(Paragraph("■ Résultats du crackage John the Ripper", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Analyser les résultats
        if cracked or "MOT DE PASSE TROUVÉ" in results:
            # Succès
            story.append(Paragraph("🎉 HASH CRACKÉ AVEC SUCCÈS", self.get_colored_style('#28a745', bold=True, size=14)))
            story.append(Spacer(1, 10))
            
            # Extraire le mot de passe trouvé
            import re
            password_match = re.search(r':([^:\n]+)$', results, re.MULTILINE)
            if password_match:
                password = password_match.group(1).strip()
                
                result_data = [
                    ['Résultat', 'Valeur'],
                    ['Hash cracké', '✅ OUI'],
                    ['Mot de passe', password],
                    ['Méthode', 'Dictionnaire (rockyou.txt)']
                ]
                
                result_table = Table(result_data, colWidths=[150, 250])
                result_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(result_table)
                story.append(Spacer(1, 15))
        else:
            # Échec
            story.append(Paragraph("❌ HASH NON CRACKÉ", self.get_colored_style('#dc3545', bold=True, size=14)))
            story.append(Spacer(1, 10))
            
            result_data = [
                ['Résultat', 'Valeur'],
                ['Hash cracké', '❌ NON'],
                ['Raison', 'Mot de passe non trouvé dans rockyou.txt'],
                ['Suggestion', 'Essayer une autre wordlist ou méthode']
            ]
            
            result_table = Table(result_data, colWidths=[150, 250])
            result_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(result_table)
            story.append(Spacer(1, 15))
        
        # Statistiques du crackage
        stats_data = [['Métrique', 'Valeur']]
        
        import re
        lines = results.split('\n')
        for line in lines:
            if 'password hash' in line and 'loaded' in line:
                stats_data.append(['Hashes chargés', '1'])
            elif 'tasks' in line:
                tasks = re.search(r'(\d+) tasks', line)
                if tasks:
                    stats_data.append(['Tâches parallèles', tasks.group(1)])
        
        if len(stats_data) > 1:
            stats_table = Table(stats_data, colWidths=[200, 200])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(stats_table)
            story.append(Spacer(1, 15))
        
        # Log détaillé
        story.append(Paragraph("Log détaillé :", self.get_colored_style('#6c757d', bold=True)))
        story.append(Spacer(1, 5))
        
        clean_results = results.replace('MOT DE PASSE TROUVÉ :', '').strip()
        story.append(Paragraph(clean_results.replace('\n', '<br/>'), self.styles['code']))
        
        # Recommandations
        story.append(Spacer(1, 20))
        story.append(Paragraph("Recommandations de sécurité :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 5))
        
        if cracked:
            recommendations = [
                "• Ce mot de passe est vulnérable et doit être changé immédiatement",
                "• Utilisez des mots de passe de 12+ caractères avec majuscules, minuscules, chiffres et symboles",
                "• Évitez les mots du dictionnaire et les informations personnelles",
                "• Implémentez une politique de mots de passe robuste",
                "• Considérez l'utilisation d'un gestionnaire de mots de passe"
            ]
        else:
            recommendations = [
                "• Le hash résiste aux attaques par dictionnaire basiques",
                "• Continuez à utiliser des mots de passe complexes",
                "• Surveillez les nouvelles techniques de crackage",
                "• Implémentez des mesures de sécurité supplémentaires (2FA, etc.)"
            ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['normal']))
        
        doc.build(story)
        return filename

    def generate_theharvester_report(self, results, domain):
        """Rapport spécialisé pour theHarvester avec mise en forme améliorée"""
        filename = f"theharvester_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("theHarvester", domain))
        
        # Titre section
        story.append(Paragraph("■ Résultats de la reconnaissance theHarvester", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Résumé des découvertes
        if isinstance(results, dict):
            summary_data = [
                ['Type de données', 'Quantité découverte'],
                ['📧 Adresses email', str(len(results.get('emails', [])))],
                ['🌐 Hosts/Sous-domaines', str(len(results.get('hosts', [])))],
                ['📍 Adresses IP', str(len(results.get('ips', [])))],
                ['📡 Numéros ASN', str(len(results.get('asns', [])))],
                ['🔗 URLs', str(len(results.get('urls', [])))]
            ]
            
            summary_table = Table(summary_data, colWidths=[250, 150])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 20))
            
            # Emails découverts
            if results.get('emails'):
                story.append(Paragraph("📧 Adresses email découvertes", self.get_colored_style('#28a745', bold=True)))
                story.append(Spacer(1, 5))
                
                email_data = [['Email', 'Domaine']]
                for email in results['emails'][:20]:  # Limiter à 20 pour l'espace
                    domain_part = email.split('@')[-1] if '@' in email else 'N/A'
                    email_data.append([email, domain_part])
                
                if len(results['emails']) > 20:
                    email_data.append([f"... et {len(results['emails']) - 20} autres", ""])
                
                email_table = Table(email_data, colWidths=[250, 150])
                email_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(email_table)
                story.append(Spacer(1, 15))
            
            # Adresses IP
            if results.get('ips'):
                story.append(Paragraph("📍 Adresses IP découvertes", self.get_colored_style('#ffc107', bold=True)))
                story.append(Spacer(1, 5))
                
                # Organiser les IPs en colonnes
                ips = results['ips'][:15]  # Limiter à 15
                ip_data = []
                for i in range(0, len(ips), 3):
                    row = ips[i:i+3]
                    while len(row) < 3:
                        row.append('')
                    ip_data.append(row)
                
                if len(results['ips']) > 15:
                    ip_data.append([f"... et {len(results['ips']) - 15} autres", "", ""])
                
                ip_table = Table(ip_data, colWidths=[130, 130, 130])
                ip_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BACKGROUND', (0, 0), (-1, -1), colors.lightyellow),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(ip_table)
                story.append(Spacer(1, 15))
            
            # Sous-domaines/Hosts
            if results.get('hosts'):
                story.append(Paragraph("🌐 Sous-domaines découverts", self.get_colored_style('#17a2b8', bold=True)))
                story.append(Spacer(1, 5))
                
                hosts_text = ""
                for i, host in enumerate(results['hosts'][:10]):  # Limiter à 10
                    hosts_text += f"• {host}\n"
                
                if len(results['hosts']) > 10:
                    hosts_text += f"... et {len(results['hosts']) - 10} autres sous-domaines"
                
                story.append(Paragraph(hosts_text.replace('\n', '<br/>'), self.styles['normal']))
                story.append(Spacer(1, 15))
        
        # Analyse de risque
        story.append(Paragraph("⚠ Analyse de risque", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 5))
        
        if isinstance(results, dict):
            email_count = len(results.get('emails', []))
            ip_count = len(results.get('ips', []))
            
            risk_level = "FAIBLE"
            risk_color = colors.green
            
            if email_count > 10 or ip_count > 5:
                risk_level = "MOYEN"
                risk_color = colors.orange
            
            if email_count > 25 or ip_count > 15:
                risk_level = "ÉLEVÉ"
                risk_color = colors.red
            
            risk_data = [
                ['Métrique', 'Valeur', 'Niveau de risque'],
                ['Exposition email', str(email_count), risk_level],
                ['Surface d\'attaque IP', str(ip_count), risk_level]
            ]
            
            risk_table = Table(risk_data, colWidths=[150, 100, 150])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('BACKGROUND', (2, 1), (2, -1), risk_color),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(risk_table)
        
        # Recommandations
        story.append(Spacer(1, 20))
        story.append(Paragraph("Recommandations de sécurité :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 5))
        
        recommendations = [
            "• Limitez l'exposition des adresses email publiques",
            "• Implémentez des politiques de filtrage anti-spam",
            "• Surveillez les domaines et sous-domaines exposés",
            "• Utilisez des adresses email de contact dédiées",
            "• Sensibilisez les employés aux techniques de reconnaissance",
            "• Surveillez votre présence sur Internet régulièrement"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['normal']))
        
        doc.build(story)
        return filename

    def generate_ssl_report(self, ssl_data, domain):
        """Rapport SSL spécialisé"""
        filename = f"ssl_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, 
                              topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []
        
        # En-tête
        self._create_header_old(story, "Vérificateur SSL/TLS", domain)
        
        # Statut
        is_valid = ssl_data.get('is_valid', False)
        remaining_days = ssl_data.get('remaining_days', 0)
        
        status_text = "✅ Certificat valide" if is_valid else "❌ Problème détecté"
        status_color = colors.green if is_valid else colors.red
        
        story.append(Paragraph(f"Statut: {status_text}", 
                             ParagraphStyle('Status', parent=self.styles['Normal'], 
                                          textColor=status_color, fontSize=12, 
                                          fontName='Helvetica-Bold')))
        story.append(Spacer(1, 15))
        
        # Tableau des informations
        story.append(Paragraph("📋 Informations du certificat", self.styles['SDVHeader']))
        
        cert_data = [
            ['Propriété', 'Valeur'],
            ['Domaine', ssl_data.get('domain', 'N/A')],
            ['Émis à', ssl_data.get('subject', {}).get('CN', 'N/A')],
            ['Émetteur', ssl_data.get('issuer', {}).get('CN', 'N/A')],
            ['Date d\'expiration', ssl_data.get('expire_date', 'N/A')],
            ['Jours restants', str(remaining_days)],
            ['Auto-signé', 'Oui' if ssl_data.get('is_self_signed') else 'Non'],
            ['Algorithme', ssl_data.get('signature_algorithm', 'N/A')],
            ['Version', str(ssl_data.get('version', 'N/A'))],
        ]
        
        cert_table = Table(cert_data, colWidths=[2*inch, 3.5*inch])
        cert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#007bff')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        
        story.append(cert_table)
        story.append(Spacer(1, 20))
        
        # SAN
        if ssl_data.get('san'):
            story.append(Paragraph("🌐 Noms alternatifs (SAN)", self.styles['SDVHeader']))
            for san in ssl_data.get('san', []):
                story.append(Paragraph(f"• {san}", self.styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Recommandations
        story.append(Paragraph("🛡 Recommandations", self.styles['SDVHeader']))
        
        if remaining_days < 0:
            story.append(Paragraph("🔴 URGENT: Le certificat est expiré !", 
                                 ParagraphStyle('Urgent', parent=self.styles['Normal'], 
                                              textColor=colors.red, fontName='Helvetica-Bold')))
        elif remaining_days < 30:
            story.append(Paragraph(f"🟡 Attention: Le certificat expire dans {remaining_days} jours", 
                                 ParagraphStyle('Warning', parent=self.styles['Normal'], 
                                              textColor=colors.orange, fontName='Helvetica-Bold')))
        else:
            story.append(Paragraph("✅ Le certificat est valide et n'expire pas prochainement", 
                                 ParagraphStyle('Good', parent=self.styles['Normal'], 
                                              textColor=colors.green)))
        
        doc.build(story)
        return filename
    
    def generate_nmap_report(self, results, target):
        """Rapport Nmap"""
        filename = f"nmap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []
        
        self._create_header_old(story, "Nmap - Scanner de Ports", target)
        
        # Analyser les résultats
        open_ports = len([line for line in results.split('\n') if '/tcp' in line and 'open' in line])
        
        # Résumé
        story.append(Paragraph("📊 Résumé du scan", self.styles['SDVHeader']))
        summary_data = [
            ['Métrique', 'Valeur'],
            ['Ports ouverts', str(open_ports)],
            ['Statut', 'Scan terminé'],
            ['Niveau de risque', 'Moyen' if open_ports > 5 else 'Faible']
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#28a745')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Résultats détaillés
        story.append(Paragraph("🔍 Résultats détaillés", self.styles['SDVHeader']))
        
        # Diviser les résultats en chunks pour éviter les pages trop longues
        results_clean = results.replace('\n', '<br/>')
        if len(results_clean) > 3000:
            results_clean = results_clean[:3000] + '<br/><br/>[... Résultats tronqués pour le PDF ...]'
        
        story.append(Paragraph(results_clean, self.styles['CodeBlock']))
        
        doc.build(story)
        return filename
    
    def generate_acunetix_report(self, acunetix_data, target):
        """Rapport spécialisé pour Acunetix"""
        filename = f"acunetix_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []
        
        # En-tête
        self._create_header_old(story, "Acunetix Web Scanner", target)
        
        # Statistiques si disponibles
        if acunetix_data.get('statistics'):
            stats = acunetix_data['statistics']
            story.append(Paragraph("📊 Statistiques du scan", self.styles['SDVHeader']))
            
            stats_data = [
                ['Métrique', 'Valeur'],
                ['Total vulnérabilités', str(stats.get('total_vulns', 0))],
                ['Vulnérabilités critiques', str(stats.get('high', 0))],
                ['Vulnérabilités moyennes', str(stats.get('medium', 0))],
                ['Vulnérabilités faibles', str(stats.get('low', 0))],
                ['Pages scannées', str(stats.get('pages_scanned', 0))],
                ['Durée du scan', str(stats.get('scan_duration', 'N/A'))]
            ]
            
            stats_table = Table(stats_data, colWidths=[2.5*inch, 2.5*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#007bff')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
            ]))
            story.append(stats_table)
            story.append(Spacer(1, 20))
        
        # Vulnérabilités détectées
        if acunetix_data.get('vulnerabilities'):
            story.append(Paragraph("🔍 Vulnérabilités détectées", self.styles['SDVHeader']))
            
            for i, vuln in enumerate(acunetix_data['vulnerabilities'], 1):
                story.append(Paragraph(f"Vulnérabilité #{i}", self.styles['Heading3']))
                
                # Déterminer la couleur selon la sévérité
                severity = vuln.get('severity', 'Low').lower()
                if severity == 'high':
                    severity_color = colors.red
                elif severity == 'medium':
                    severity_color = colors.orange
                else:
                    severity_color = colors.green
                
                vuln_data = [
                    ['Propriété', 'Valeur'],
                    ['Nom', vuln.get('name', 'N/A')],
                    ['Sévérité', vuln.get('severity', 'N/A')],
                    ['Description', vuln.get('description', 'N/A')[:300] + '...' if len(vuln.get('description', '')) > 300 else vuln.get('description', 'N/A')],
                    ['Recommandation', vuln.get('recommendation', 'N/A')[:300] + '...' if len(vuln.get('recommendation', '')) > 300 else vuln.get('recommendation', 'N/A')]
                ]
                
                vuln_table = Table(vuln_data, colWidths=[1.5*inch, 4*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), severity_color),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 15))
        
        # Recommandations globales
        story.append(Paragraph("🛡 Recommandations globales", self.styles['SDVHeader']))
        
        if acunetix_data.get('statistics', {}).get('high', 0) > 0:
            story.append(Paragraph("🔴 URGENT: Des vulnérabilités critiques ont été détectées", 
                                 ParagraphStyle('Critical', parent=self.styles['Normal'], 
                                              textColor=colors.red, fontName='Helvetica-Bold')))
        
        recommendations = [
            "• Corrigez en priorité les vulnérabilités critiques et moyennes",
            "• Effectuez des tests de régression après les corrections",
            "• Planifiez des scans réguliers pour maintenir la sécurité",
            "• Formez l'équipe de développement aux bonnes pratiques de sécurité",
            "• Implémentez un processus de développement sécurisé (SDLC)"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['Normal']))
        
        doc.build(story)
        return filename

    def generate_nmap_nse_report(self, results, target, script):
        """Rapport spécialisé pour Nmap NSE avec mise en forme améliorée"""
        filename = f"nmap_nse_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("Nmap NSE", f"{target} - Script: {script}"))
        
        # Titre section
        story.append(Paragraph("■ Résultats du Scan Nmap NSE", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Analyse du script utilisé
        script_analysis = self._analyze_nse_script(script)
        story.append(Paragraph(f"<b>Type de script :</b> {script_analysis['category']}", self.styles['normal']))
        story.append(Paragraph(f"<b>Objectif :</b> {script_analysis['purpose']}", self.styles['normal']))
        story.append(Spacer(1, 15))
        
        # Extraction des informations importantes
        scan_info = self._extract_nse_info(results, script)
        
        # Tableau des découvertes
        if scan_info['discoveries']:
            discovery_data = [['Type', 'Valeur', 'Statut']]
            for discovery in scan_info['discoveries']:
                discovery_data.append([discovery['type'], discovery['value'], discovery['status']])
            
            discovery_table = Table(discovery_data, colWidths=[1.5*inch, 3*inch, 1*inch])
            discovery_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ]))
            
            story.append(Paragraph("📊 Découvertes du scan :", self.get_colored_style('#28a745', bold=True)))
            story.append(Spacer(1, 10))
            story.append(discovery_table)
            story.append(Spacer(1, 20))
        
        # Détails techniques
        story.append(Paragraph("🔍 Détails techniques :", self.get_colored_style('#007bff', bold=True)))
        story.append(Spacer(1, 10))
        
        # Nettoyage et formatage des résultats
        cleaned_results = self._clean_nmap_output(results)
        story.append(Paragraph(f"<font name='Courier' size='8'>{cleaned_results}</font>", self.styles['normal']))
        story.append(Spacer(1, 20))
        
        # Recommandations selon le script
        recommendations = self._get_nse_recommendations(script, scan_info)
        story.append(Paragraph("🛡 Recommandations de sécurité :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 10))
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _analyze_nse_script(self, script):
        """Analyse le type de script NSE"""
        script_info = {
            'http-title': {'category': 'Reconnaissance Web', 'purpose': 'Récupération des titres de pages web'},
            'ssl-cert': {'category': 'Analyse SSL/TLS', 'purpose': 'Examen des certificats SSL'},
            'ftp-anon': {'category': 'Test d\'authentification', 'purpose': 'Détection FTP anonyme'},
            'ssh-hostkey': {'category': 'Cryptographie', 'purpose': 'Énumération des clés SSH'},
            'vuln': {'category': 'Détection de vulnérabilités', 'purpose': 'Recherche de failles de sécurité'},
            'smb-vuln-ms17-010': {'category': 'Test de vulnérabilité', 'purpose': 'Détection EternalBlue'},
            'http-enum': {'category': 'Énumération Web', 'purpose': 'Découverte de répertoires et fichiers'},
            'smb-os-discovery': {'category': 'Reconnaissance OS', 'purpose': 'Identification du système d\'exploitation'},
            'dns-zone-transfer': {'category': 'Test DNS', 'purpose': 'Tentative de transfert de zone DNS'},
            'http-methods': {'category': 'Analyse HTTP', 'purpose': 'Énumération des méthodes HTTP'},
            'http-headers': {'category': 'Analyse HTTP', 'purpose': 'Analyse des en-têtes HTTP'},
            'ssl-enum-ciphers': {'category': 'Cryptographie', 'purpose': 'Énumération des chiffrements SSL'},
        }
        return script_info.get(script, {'category': 'Script personnalisé', 'purpose': 'Analyse spécialisée'})

    def _extract_nse_info(self, results, script):
        """Extrait les informations importantes du scan NSE"""
        import re
        
        discoveries = []
        
        # Extraction selon le type de script
        if 'http-title' in script:
            titles = re.findall(r'title:\s*(.+)', results, re.IGNORECASE)
            for title in titles:
                discoveries.append({'type': 'Titre de page', 'value': title.strip(), 'status': 'Détecté'})
        
        elif 'ssl-cert' in script:
            subjects = re.findall(r'subject:\s*(.+)', results, re.IGNORECASE)
            for subject in subjects:
                discoveries.append({'type': 'Certificat SSL', 'value': subject.strip(), 'status': 'Détecté'})
        
        elif 'ftp-anon' in script:
            if 'Anonymous FTP login allowed' in results:
                discoveries.append({'type': 'FTP Anonyme', 'value': 'Accès autorisé', 'status': 'Vulnérable'})
            else:
                discoveries.append({'type': 'FTP Anonyme', 'value': 'Accès refusé', 'status': 'Sécurisé'})
        
        elif 'ssh-hostkey' in script:
            keys = re.findall(r'(\d+)\s+(\w+):([a-f0-9:]+)', results)
            for bits, key_type, fingerprint in keys:
                discoveries.append({'type': f'Clé SSH {key_type}', 'value': f'{bits} bits', 'status': 'Détectée'})
        
        elif 'vuln' in script:
            if 'VULNERABLE' in results.upper():
                discoveries.append({'type': 'Vulnérabilité', 'value': 'Faille détectée', 'status': 'CRITIQUE'})
            else:
                discoveries.append({'type': 'Vulnérabilité', 'value': 'Aucune faille détectée', 'status': 'Sécurisé'})
        
        # Extraction des ports (général)
        ports = re.findall(r'(\d+)/tcp\s+open\s+(\w+)', results)
        for port, service in ports:
            discoveries.append({'type': 'Port ouvert', 'value': f'TCP/{port} ({service})', 'status': 'Accessible'})
        
        # Extraction des IPs
        ips = re.findall(r'Nmap scan report for .* \(([\d.]+)\)', results)
        for ip in ips:
            discoveries.append({'type': 'Adresse IP', 'value': ip, 'status': 'Résolue'})
        
        return {'discoveries': discoveries}

    def _clean_nmap_output(self, results):
        """Nettoie et formate la sortie Nmap"""
        import re
        
        # Supprime les caractères spéciaux et nettoie
        cleaned = re.sub(r'[^\x20-\x7E\n]', '', results)
        
        # Remplace les retours à la ligne par des <br/> pour le PDF
        cleaned = cleaned.replace('\n', '<br/>')
        
        # Limite à 2500 caractères pour le PDF
        if len(cleaned) > 2500:
            cleaned = cleaned[:2500] + "<br/><br/>[... Résultats tronqués pour optimiser l'affichage PDF ...]"
        
        return cleaned

    def _get_nse_recommendations(self, script, scan_info):
        """Recommandations selon le script NSE utilisé"""
        recommendations = []
        
        if 'http-title' in script:
            recommendations.extend([
                "Vérifiez que les titres des pages ne révèlent pas d'informations sensibles",
                "Assurez-vous que les pages d'erreur ne divulguent pas la technologie utilisée",
                "Configurez des en-têtes de sécurité appropriés (CSP, HSTS, X-Frame-Options)",
                "Évitez d'exposer des informations de version dans les titres"
            ])
        
        elif 'ssl-cert' in script:
            recommendations.extend([
                "Vérifiez la validité et la date d'expiration des certificats SSL",
                "Utilisez des algorithmes de chiffrement forts (TLS 1.2+ minimum)",
                "Configurez HSTS pour forcer les connexions HTTPS",
                "Surveillez l'expiration des certificats avec des alertes automatiques"
            ])
        
        elif 'vuln' in script:
            has_vuln = any(d for d in scan_info['discoveries'] if d['status'] == 'CRITIQUE')
            if has_vuln:
                recommendations.extend([
                    "🚨 URGENT : Appliquez immédiatement les correctifs pour les vulnérabilités critiques",
                    "Isolez temporairement les systèmes vulnérables si possible",
                    "Effectuez un scan de vérification après correction",
                    "Mettez en place une surveillance continue des vulnérabilités"
                ])
            else:
                recommendations.extend([
                    "Continuez à surveiller régulièrement les nouvelles vulnérabilités",
                    "Maintenez vos systèmes à jour avec les derniers correctifs de sécurité",
                    "Effectuez des scans de vulnérabilités périodiques"
                ])
        
        elif 'ftp-anon' in script:
            recommendations.extend([
                "Désactivez l'accès FTP anonyme si non nécessaire",
                "Utilisez SFTP ou FTPS pour sécuriser les transferts de fichiers",
                "Limitez les permissions des comptes FTP au strict minimum",
                "Surveillez les connexions FTP dans vos logs"
            ])
        
        elif 'ssh-hostkey' in script:
            recommendations.extend([
                "Vérifiez l'authenticité des clés SSH affichées",
                "Utilisez des clés SSH fortes (RSA 2048+ bits ou Ed25519)",
                "Désactivez l'authentification par mot de passe SSH",
                "Surveillez les changements de clés hôte SSH"
            ])
        
        else:
            recommendations.extend([
                "Analysez attentivement les résultats du script NSE",
                "Vérifiez si les services détectés sont nécessaires à votre activité",
                "Appliquez le principe du moindre privilège sur tous les services",
                "Surveillez régulièrement l'exposition de vos services réseau",
                "Documentez les services légitimes pour future référence"
            ])
        
        return recommendations

    def generate_nikto_report(self, results, target):
        """Rapport spécialisé pour Nikto avec mise en forme améliorée"""
        filename = f"nikto_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("Nikto", target))
        
        # Titre section
        story.append(Paragraph("■ Résultats du Scan Nikto", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Parsing intelligent des résultats Nikto
        nikto_analysis = self._parse_nikto_results(results)
        
        # Résumé des découvertes
        summary_data = [
            ['Métrique', 'Valeur'],
            ['🔍 Vulnérabilités trouvées', str(nikto_analysis['vulnerabilities_count'])],
            ['📁 Fichiers exposés', str(nikto_analysis['files_exposed'])],
            ['🎯 Niveau de risque', nikto_analysis['risk_level']]
        ]
        
        summary_table = Table(summary_data, colWidths=[200, 200])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Vulnérabilités détectées
        if nikto_analysis['critical_vulns']:
            story.append(Paragraph("🚨 Vulnérabilités détectées :", self.get_colored_style('#dc3545', bold=True)))
            story.append(Spacer(1, 10))
            
            for i, vuln in enumerate(nikto_analysis['critical_vulns'][:5], 1):
                story.append(Paragraph(f"<b>#{i}:</b> {vuln['description']}", self.styles['normal']))
                story.append(Paragraph(f"<b>Référence:</b> {vuln['reference']}", self.styles['normal']))
                story.append(Spacer(1, 8))
        
        # Détails techniques
        story.append(Paragraph("🔍 Log détaillé du scan :", self.get_colored_style('#007bff', bold=True)))
        story.append(Spacer(1, 10))
        
        # Nettoyer et formater les résultats
        cleaned_results = self._clean_nikto_output(results)
        story.append(Paragraph(f"<font name='Courier' size='8'>{cleaned_results}</font>", self.styles['normal']))
        story.append(Spacer(1, 20))
        
        # Recommandations
        recommendations = self._get_nikto_recommendations(nikto_analysis)
        story.append(Paragraph("🛡 Recommandations de sécurité :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 10))
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _parse_nikto_results(self, results):
        """Parse intelligent des résultats Nikto"""
        import re
        
        analysis = {
            'vulnerabilities_count': 0,
            'files_exposed': 0,
            'risk_level': 'FAIBLE',
            'critical_vulns': [],
            'sensitive_files': [],
            'missing_headers': []
        }
        
        try:
            lines = results.split('\n')
            
            for line in lines:
                # Compter les vulnérabilités
                if any(keyword in line.lower() for keyword in ['osvdb', 'cve-', 'vulnerable']):
                    analysis['vulnerabilities_count'] += 1
                    
                    # Extraire la référence
                    ref = "Nikto DB"
                    if 'OSVDB-' in line:
                        osvdb_match = re.search(r'OSVDB-(\d+)', line)
                        if osvdb_match:
                            ref = f"OSVDB-{osvdb_match.group(1)}"
                    elif 'CVE-' in line:
                        cve_match = re.search(r'(CVE-\d{4}-\d+)', line)
                        if cve_match:
                            ref = cve_match.group(1)
                    
                    analysis['critical_vulns'].append({
                        'type': 'Web Vulnerability',
                        'description': line.strip()[:80] + '...' if len(line.strip()) > 80 else line.strip(),
                        'reference': ref
                    })
                
                # Compter les fichiers exposés
                elif any(path in line.lower() for path in ['/admin', '/config', '/backup', '/test']):
                    analysis['files_exposed'] += 1
            
            # Déterminer le niveau de risque
            if analysis['vulnerabilities_count'] >= 3:
                analysis['risk_level'] = 'ÉLEVÉ'
            elif analysis['vulnerabilities_count'] >= 1:
                analysis['risk_level'] = 'MOYEN'
                
        except Exception as e:
            print(f"[DEBUG] Erreur parsing Nikto: {e}")
        
        return analysis

    def _clean_nikto_output(self, results):
        """Nettoie et formate la sortie Nikto"""
        import re
        
        # Supprime les caractères spéciaux
        cleaned = re.sub(r'[^\x20-\x7E\n]', '', results)
        
        # Remplace les retours à la ligne par des <br/>
        cleaned = cleaned.replace('\n', '<br/>')
        
        # Limite la longueur pour le PDF
        if len(cleaned) > 2500:
            cleaned = cleaned[:2500] + "<br/><br/>[... Log tronqué pour le PDF ...]"
        
        return cleaned

    def _get_nikto_recommendations(self, analysis):
        """Recommandations selon les vulnérabilités Nikto trouvées"""
        recommendations = []
        
        if analysis['risk_level'] == 'ÉLEVÉ':
            recommendations.extend([
                "🚨 URGENT : Corrigez les vulnérabilités critiques détectées",
                "Effectuez un audit de sécurité complet de l'application web"
            ])
        
        recommendations.extend([
            "Configurez les en-têtes de sécurité manquants (X-Frame-Options, CSP)",
            "Supprimez ou protégez les fichiers/dossiers sensibles exposés",
            "Maintenez votre serveur web et vos applications à jour",
            "Effectuez des scans Nikto réguliers",
            "Implémentez un WAF (Web Application Firewall)"
        ])
        
        return recommendations

    # ===== FONCTIONS AMASS INTÉGRÉES DANS LA CLASSE =====
    def generate_amass_report(self, results, domain, nb_lignes):
        """Rapport spécialisé pour Amass avec mise en forme magnifique comme Hydra"""
        filename = f"amass_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header SDV
        story.extend(self._create_header("OWASP Amass", domain))
        
        # Titre section avec style
        story.append(Paragraph("■ Résultats de la Reconnaissance Amass", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Parse intelligent des résultats
        amass_analysis = self._parse_amass_results(results, domain)
        
        # TABLEAU RÉSUMÉ STYLÉ comme Hydra
        if amass_analysis['exposure_level'] == 'ÉLEVÉ':
            status_color = colors.red
            status_text = "🚨 EXPOSITION ÉLEVÉE"
        elif amass_analysis['exposure_level'] == 'MOYEN':
            status_color = colors.orange  
            status_text = "⚠ EXPOSITION MODÉRÉE"
        else:
            status_color = colors.green
            status_text = "✅ EXPOSITION FAIBLE"
        
        story.append(Paragraph(status_text, self.get_colored_style('#dc3545' if amass_analysis['exposure_level'] == 'ÉLEVÉ' else '#ffc107' if amass_analysis['exposure_level'] == 'MOYEN' else '#28a745', bold=True, size=14)))
        story.append(Spacer(1, 10))
        
        # Tableau des métriques principales
        summary_data = [
            ['Métrique', 'Valeur'],
            ['🎯 Domaine cible', domain],
            ['🌐 Sous-domaines découverts', str(nb_lignes)],
            ['📍 Adresses IP uniques', str(len(amass_analysis['unique_ips']))],
            ['🔥 Sous-domaines sensibles', str(len(amass_analysis['interesting_subdomains']))],
            ['📊 Niveau d\'exposition', amass_analysis['exposure_level']]
        ]
        
        summary_table = Table(summary_data, colWidths=[200, 200])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Sous-domaines sensibles détectés (style Hydra credentials)
        if amass_analysis['interesting_subdomains']:
            story.append(Paragraph("🔥 SOUS-DOMAINES SENSIBLES DÉTECTÉS", self.get_colored_style('#dc3545', bold=True, size=14)))
            story.append(Spacer(1, 10))
            
            # Tableau des sous-domaines critiques
            sensitive_data = [['Sous-domaine', 'Type', 'Niveau de Risque']]
            for subdomain_info in amass_analysis['interesting_subdomains'][:10]:  # Top 10
                risk_color = colors.red if subdomain_info['risk_level'] == 'ÉLEVÉ' else colors.orange
                sensitive_data.append([
                    subdomain_info['subdomain'], 
                    subdomain_info['type'], 
                    subdomain_info['risk_level']
                ])
            
            sensitive_table = Table(sensitive_data, colWidths=[2.5*inch, 1.5*inch, 1*inch])
            sensitive_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(sensitive_table)
            story.append(Spacer(1, 15))
        
        # Analyse des adresses IP (style technique)
        if amass_analysis['ip_analysis']:
            story.append(Paragraph("📍 Analyse des adresses IP :", self.get_colored_style('#007bff', bold=True)))
            story.append(Spacer(1, 10))
            
            ip_data = [['Adresse IP', 'Occurrences', 'Services détectés']]
            for ip_info in amass_analysis['ip_analysis'][:8]:  # Top 8 IPs
                ip_data.append([
                    ip_info['ip'], 
                    str(ip_info['count']), 
                    ', '.join(ip_info['services'][:3])  # 3 premiers services
                ])
            
            ip_table = Table(ip_data, colWidths=[1.5*inch, 1*inch, 2.5*inch])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(ip_table)
            story.append(Spacer(1, 20))
        
        # Échantillon des résultats (style log Hydra)
        story.append(Paragraph("🔍 Échantillon des découvertes :", self.get_colored_style('#6c757d', bold=True)))
        story.append(Spacer(1, 5))
        
        # Top 30 résultats les plus intéressants
        sample_results = '\n'.join(results.split('\n')[:30])
        if len(results.split('\n')) > 30:
            sample_results += f"\n\n... et {len(results.split('\n'))-30} autres sous-domaines découverts"
        
        cleaned_sample = sample_results.replace('\n', '<br/>')
        story.append(Paragraph(f"<font name='Courier' size='8'>{cleaned_sample}</font>", self.styles['code']))
        story.append(Spacer(1, 20))
        
        # Recommandations de sécurité (style Hydra)
        story.append(Paragraph("🛡 Recommandations de sécurité prioritaires :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 5))
        
        recommendations = self._get_amass_recommendations(amass_analysis, nb_lignes)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _parse_amass_results(self, results, domain):
        """Parse intelligent des résultats Amass"""
        import re
        
        analysis = {
            'unique_ips': set(),
            'interesting_subdomains': [],
            'exposure_level': 'FAIBLE',
            'ip_analysis': []
        }
        
        lines = results.strip().split('\n')
        ip_counts = {}
        
        # Mots-clés critiques pour sous-domaines sensibles
        critical_keywords = {
            'admin': 'ÉLEVÉ', 'api': 'MOYEN', 'dev': 'ÉLEVÉ', 'test': 'ÉLEVÉ',
            'staging': 'MOYEN', 'prod': 'ÉLEVÉ', 'mail': 'MOYEN', 'ftp': 'MOYEN',
            'vpn': 'ÉLEVÉ', 'portal': 'MOYEN', 'login': 'ÉLEVÉ', 'secure': 'MOYEN',
            'internal': 'ÉLEVÉ', 'priv': 'ÉLEVÉ', 'backup': 'ÉLEVÉ', 'db': 'ÉLEVÉ',
            'database': 'ÉLEVÉ', 'sql': 'ÉLEVÉ', 'ssh': 'MOYEN'
        }
        
        for line in lines:
            if line.strip():
                # Extraire les IPs et compter
                ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                for ip in ip_matches:
                    analysis['unique_ips'].add(ip)
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                
                # Identifier sous-domaines sensibles
                for keyword, risk in critical_keywords.items():
                    if keyword in line.lower():
                        # Extraire le sous-domaine complet
                        subdomain_match = re.search(r'([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')', line)
                        if subdomain_match:
                            subdomain = subdomain_match.group(1)
                            if not any(s['subdomain'] == subdomain for s in analysis['interesting_subdomains']):
                                analysis['interesting_subdomains'].append({
                                    'subdomain': subdomain,
                                    'type': keyword.upper(),
                                    'risk_level': risk
                                })
        
        # Analyse des IPs les plus fréquentes
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            # Détecter les services depuis les lignes contenant cette IP
            services = set()
            for line in lines:
                if ip in line:
                    if 'mail' in line.lower(): services.add('Mail')
                    if 'web' in line.lower(): services.add('Web')
                    if 'ftp' in line.lower(): services.add('FTP')
                    if 'api' in line.lower(): services.add('API')
            
            analysis['ip_analysis'].append({
                'ip': ip,
                'count': count,
                'services': list(services) if services else ['Unknown']
            })
        
        # Déterminer niveau d'exposition
        total_subdomains = len(lines)
        high_risk_count = len([s for s in analysis['interesting_subdomains'] if s['risk_level'] == 'ÉLEVÉ'])
        
        if total_subdomains > 100 or high_risk_count > 5:
            analysis['exposure_level'] = 'ÉLEVÉ'
        elif total_subdomains > 50 or high_risk_count > 2:
            analysis['exposure_level'] = 'MOYEN'
        
        return analysis

    def _get_amass_recommendations(self, analysis, nb_lignes):
        """Recommandations adaptées au niveau d'exposition"""
        recommendations = []
        
        if analysis['exposure_level'] == 'ÉLEVÉ':
            recommendations.extend([
                "🚨 URGENT : Surface d'attaque très étendue détectée",
                "Auditez immédiatement tous les sous-domaines sensibles (admin, dev, api)",
                "Désactivez ou sécurisez les sous-domaines non essentiels"
            ])
        
        if len(analysis['interesting_subdomains']) > 0:
            recommendations.append("Examinez en priorité les sous-domaines d'administration et de développement")
        
        if nb_lignes > 100:
            recommendations.append("Considérez l'implémentation d'un WAF pour protéger vos nombreux sous-domaines")
        
        recommendations.extend([
            "Surveillez régulièrement l'apparition de nouveaux sous-domaines avec des outils de monitoring",
            "Implémentez des certificats SSL/TLS valides sur tous les sous-domaines exposés",
            "Configurez une politique de sous-domaines stricte et documentée",
            "Effectuez des audits périodiques de votre surface d'attaque externe",
            "Mettez en place des alertes automatiques pour les nouveaux sous-domaines détectés"
        ])
        
        return recommendations

    def generate_sqlmap_report(self, results, target):
        """Rapport spécialisé pour SQLMap avec analyse détaillée"""
        filename = f"sqlmap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header SDV
        story.extend(self._create_header("SQLMap", target))
        
        # Titre section
        story.append(Paragraph("■ Résultats de l'Analyse SQLMap", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Parser intelligent des résultats
        sqlmap_analysis = self._parse_sqlmap_results(results)
        
        # STATUT CRITIQUE avec couleur adaptée
        if sqlmap_analysis['is_vulnerable']:
            status_text = "🚨 VULNÉRABILITÉS SQL CRITIQUES DÉTECTÉES"
            status_color = '#dc3545'
            status_bg = colors.red
        else:
            status_text = "✅ AUCUNE VULNÉRABILITÉ SQL DÉTECTÉE"
            status_color = '#28a745'  
            status_bg = colors.green
        
        story.append(Paragraph(status_text, self.get_colored_style(status_color, bold=True, size=16)))
        story.append(Spacer(1, 15))
        
        # Tableau résumé avec style professionnel
        summary_data = [
            ['Métrique', 'Valeur'],
            ['🎯 URL analysée', target[:60] + '...' if len(target) > 60 else target],
            ['💉 Vulnérabilités SQL', '🚨 OUI - CRITIQUE' if sqlmap_analysis['is_vulnerable'] else '✅ NON'],
            ['🗃 SGBD détecté', sqlmap_analysis['database_type']],
            ['🔍 Paramètres testés', str(sqlmap_analysis['parameters_tested'])],
            ['⚡ Techniques utilisées', sqlmap_analysis['techniques_found']],
            ['🎯 Niveau de risque', sqlmap_analysis['risk_level']]
        ]
        
        summary_table = Table(summary_data, colWidths=[180, 220])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), status_bg),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Log technique détaillé
        story.append(Paragraph("🔍 Extrait du log SQLMap :", self.get_colored_style('#007bff', bold=True)))
        story.append(Spacer(1, 10))
        
        # Nettoyer et limiter le log
        cleaned_log = self._clean_sqlmap_output(results)
        story.append(Paragraph(f"<font name='Courier' size='7'>{cleaned_log}</font>", self.styles['normal']))
        story.append(Spacer(1, 20))
        
        # Recommandations CRITIQUES
        story.append(Paragraph("🛡 RECOMMANDATIONS DE SÉCURITÉ URGENTES", self.get_colored_style('#dc3545', bold=True, size=14)))
        story.append(Spacer(1, 10))
        
        recommendations = self._get_sqlmap_recommendations(sqlmap_analysis)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _parse_sqlmap_results(self, results):
        """Parse intelligent des résultats SQLMap"""
        import re
        
        analysis = {
            'is_vulnerable': False,
            'database_type': 'Non détecté',
            'parameters_tested': 0,
            'techniques_found': 'Aucune',
            'risk_level': 'FAIBLE'
        }
        
        try:
            # Détecter vulnérabilités
            if any(keyword in results.lower() for keyword in ['vulnerable', 'injection', 'payload worked']):
                analysis['is_vulnerable'] = True
                analysis['risk_level'] = 'CRITIQUE'
            
            # Extraire le type de base de données
            if 'mysql' in results.lower():
                analysis['database_type'] = 'MySQL'
            elif 'postgresql' in results.lower():
                analysis['database_type'] = 'PostgreSQL'
            elif 'oracle' in results.lower():
                analysis['database_type'] = 'Oracle'
            elif 'mssql' in results.lower():
                analysis['database_type'] = 'SQL Server'
            
            # Compter paramètres testés
            param_matches = re.findall(r'testing.*parameter.*\'([^\']+)\'', results, re.IGNORECASE)
            analysis['parameters_tested'] = len(set(param_matches)) if param_matches else 1
            
            # Extraire techniques d'injection
            techniques = []
            if 'boolean' in results.lower():
                techniques.append('Boolean-based')
            if 'time' in results.lower():
                techniques.append('Time-based')
            if 'union' in results.lower():
                techniques.append('UNION query')
            
            analysis['techniques_found'] = ', '.join(techniques) if techniques else 'Standard'
                
        except Exception as e:
            print(f"[DEBUG] Erreur parsing SQLMap: {e}")
        
        return analysis

    def _clean_sqlmap_output(self, results):
        """Nettoie la sortie SQLMap pour le PDF"""
        import re
        
        # Prendre les parties les plus importantes
        lines = results.split('\n')
        important_lines = []
        
        for line in lines[:50]:  # Limiter à 50 lignes
            if any(keyword in line.lower() for keyword in 
                   ['target', 'parameter', 'injectable', 'payload', 'database', 'version']):
                important_lines.append(line.strip())
        
        # Si pas assez de lignes importantes, prendre le début
        if len(important_lines) < 10:
            important_lines = lines[:30]
        
        cleaned = '\n'.join(important_lines)
        cleaned = re.sub(r'[^\x20-\x7E\n]', '', cleaned)  # Caractères ASCII only
        cleaned = cleaned.replace('\n', '<br/>')
        
        if len(cleaned) > 2000:
            cleaned = cleaned[:2000] + '<br/>[... Log tronqué pour le PDF ...]'
        
        return cleaned

    def _get_sqlmap_recommendations(self, analysis):
        """Recommandations selon les vulnérabilités SQLMap"""
        recommendations = []
        
        if analysis['is_vulnerable']:
            recommendations.extend([
                "🚨 URGENT : Vulnérabilités d'injection SQL critiques détectées",
                "Corrigez immédiatement en utilisant des requêtes préparées (prepared statements)",
                "Validez et échappez toutes les entrées utilisateur",
                "Implémentez une whitelist stricte pour les paramètres"
            ])
        else:
            recommendations.extend([
                "Aucune vulnérabilité SQL détectée - Bonne pratique de sécurité",
                "Continuez à utiliser des requêtes préparées"
            ])
        
        recommendations.extend([
            "Surveillez les logs de base de données pour détecter les tentatives d'injection",
            "Implémentez un WAF (Web Application Firewall)",
            "Effectuez des audits de sécurité réguliers",
            "Maintenez vos systèmes de base de données à jour"
        ])
        
        return recommendations

    def generate_postman_report(self, api_data, response_data):
        """Rapport spécialisé pour Postman/API Testing"""
        filename = f"postman_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("API Testing (Postman)", api_data.get('url', 'N/A')))
        
        # Titre section
        story.append(Paragraph("■ Résultats du Test d'API", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Statut de la requête
        status_code = response_data.get('status_code', 0)
        if 200 <= status_code < 300:
            status_text = f"✅ SUCCÈS - Code {status_code}"
            status_color = '#28a745'
            status_bg = colors.green
        elif 400 <= status_code < 500:
            status_text = f"⚠️ ERREUR CLIENT - Code {status_code}"
            status_color = '#ffc107'
            status_bg = colors.orange
        elif 500 <= status_code:
            status_text = f"🚨 ERREUR SERVEUR - Code {status_code}"
            status_color = '#dc3545'
            status_bg = colors.red
        else:
            status_text = f"❓ STATUT INCONNU - Code {status_code}"
            status_color = '#6c757d'
            status_bg = colors.gray
        
        story.append(Paragraph(status_text, self.get_colored_style(status_color, bold=True, size=16)))
        story.append(Spacer(1, 15))
        
        # Détails de la requête
        request_data = [
            ['Paramètre', 'Valeur'],
            ['🌐 URL', api_data.get('url', 'N/A')],
            ['⚡ Méthode HTTP', api_data.get('method', 'GET')],
            ['📦 Corps de requête', api_data.get('payload', 'Aucun')[:100] + '...' if len(api_data.get('payload', '')) > 100 else api_data.get('payload', 'Aucun')],
            ['📅 Date du test', datetime.now().strftime('%d/%m/%Y à %H:%M:%S')]
        ]
        
        request_table = Table(request_data, colWidths=[150, 250])
        request_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        story.append(request_table)
        story.append(Spacer(1, 20))
        
        # Résultats
        results_text = f"Code de statut: {status_code}\n\n"
        if response_data.get('headers'):
            results_text += "En-têtes:\n"
            for key, value in response_data['headers'].items():
                results_text += f"  {key}: {value}\n"
        
        if response_data.get('body'):
            body_preview = response_data['body'][:1000]
            if len(response_data['body']) > 1000:
                body_preview += "\n[... Contenu tronqué ...]"
            results_text += f"\nCorps de réponse:\n{body_preview}"
        
        story.append(Paragraph("🔍 Détails de la réponse :", self.get_colored_style('#007bff', bold=True)))
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"<font name='Courier' size='8'>{results_text.replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br/>')}</font>", self.styles['normal']))
        
        doc.build(story)
        return filename


    def generate_metasploit_report(self, results, metasploit_data):
        """Rapport spécialisé pour Metasploit avec analyse d'exploitation"""
        filename = f"metasploit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("Metasploit Framework", metasploit_data.get('target_info', 'N/A')))
        
        # Titre section
        story.append(Paragraph("■ Résultats de l'Exploitation Metasploit", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Analyse des résultats
        exploit_analysis = self._analyze_metasploit_results(results)
        
        # Statut de l'exploitation
        if exploit_analysis['session_created']:
            status_text = "🎉 EXPLOITATION RÉUSSIE - SESSION OUVERTE"
            status_color = '#28a745'
            status_bg = colors.green
        elif exploit_analysis['exploit_completed']:
            status_text = "⚠️ EXPLOIT TERMINÉ - AUCUNE SESSION"
            status_color = '#ffc107'
            status_bg = colors.orange
        elif exploit_analysis['has_error']:
            status_text = "❌ ÉCHEC DE L'EXPLOITATION"
            status_color = '#dc3545'
            status_bg = colors.red
        else:
            status_text = "ℹ️ EXPLOITATION EXÉCUTÉE"
            status_color = '#17a2b8'
            status_bg = colors.blue
        
        story.append(Paragraph(status_text, self.get_colored_style(status_color, bold=True, size=16)))
        story.append(Spacer(1, 15))
        
        # Détails de l'exploitation
        exploit_details = [
            ['Paramètre', 'Valeur'],
            ['🎯 Module d\'exploit', metasploit_data.get('exploit', 'N/A')],
            ['🌐 Cible (RHOST)', metasploit_data.get('rhost', 'N/A')],
            ['🔌 Port (RPORT)', metasploit_data.get('rport', 'N/A')],
            ['💥 Payload', metasploit_data.get('payload', 'Aucun') or 'Aucun'],
            ['📅 Date d\'exploitation', datetime.now().strftime('%d/%m/%Y à %H:%M:%S')],
            ['🎖️ Statut', exploit_analysis['status']]
        ]
        
        exploit_table = Table(exploit_details, colWidths=[150, 250])
        exploit_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), status_bg),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        story.append(exploit_table)
        story.append(Spacer(1, 20))
        
        # Log technique détaillé
        story.append(Paragraph("🔍 Log détaillé de l'exploitation :", self.get_colored_style('#007bff', bold=True)))
        story.append(Spacer(1, 10))
        
        # Nettoyer et formater les résultats
        cleaned_results = self._clean_metasploit_output(results)
        story.append(Paragraph(f"<font name='Courier' size='7'>{cleaned_results}</font>", self.styles['normal']))
        story.append(Spacer(1, 20))
        
        # Recommandations
        recommendations = self._get_metasploit_recommendations(exploit_analysis, metasploit_data)
        story.append(Paragraph("🛡️ Recommandations de sécurité :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 10))
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _analyze_metasploit_results(self, results):
        """Analyse les résultats Metasploit"""
        import re
        
        analysis = {
            'session_created': False,
            'exploit_completed': False,
            'has_error': False,
            'status': 'Inconnu',
            'sessions': []
        }
        
        try:
            # Détecter les sessions créées
            if 'Meterpreter session' in results or 'Command shell session' in results:
                analysis['session_created'] = True
                analysis['status'] = 'Session ouverte'
                
                # Extraire les sessions
                session_matches = re.findall(r'(Meterpreter|Command shell) session (\d+) opened', results)
                for session_type, session_id in session_matches:
                    analysis['sessions'].append({
                        'id': session_id,
                        'type': session_type,
                        'info': f'{session_type} session'
                    })
            
            # Détecter exploit terminé sans session
            elif 'Exploit completed, but no session was created' in results:
                analysis['exploit_completed'] = True
                analysis['status'] = 'Exploit terminé sans session'
            
            # Détecter erreurs
            elif any(error in results.lower() for error in ['error', 'failed', 'exception']):
                analysis['has_error'] = True
                analysis['status'] = 'Erreur détectée'
            
            else:
                analysis['status'] = 'Exploitation exécutée'
                
        except Exception as e:
            print(f"[DEBUG] Erreur analyse Metasploit: {e}")
            analysis['status'] = 'Erreur d\'analyse'
        
        return analysis

    def _clean_metasploit_output(self, results):
        """Nettoie la sortie Metasploit pour le PDF"""
        import re
        
        # Supprimer les codes ANSI
        cleaned = re.sub(r'\x1b[^m]*m', '', results)
        
        # Supprimer les lignes de démarrage
        lines = cleaned.split('\n')
        filtered_lines = []
        
        for line in lines:
            if not any(skip in line for skip in [
                'Starting the Metasploit Framework',
                'msf >',
                'msf6 >',
                'Call with "',
                'resource >'
            ]):
                filtered_lines.append(line.strip())
        
        cleaned = '\n'.join(filtered_lines)
        cleaned = re.sub(r'[^\x20-\x7E\n]', '', cleaned)  # ASCII only
        cleaned = cleaned.replace('\n', '<br/>')
        
        if len(cleaned) > 2500:
            cleaned = cleaned[:2500] + '<br/>[... Log tronqué pour le PDF ...]'
        
        return cleaned

    def _get_metasploit_recommendations(self, analysis, metasploit_data):
        """Recommandations selon les résultats Metasploit"""
        recommendations = []
        
        if analysis['session_created']:
            recommendations.extend([
                "🚨 CRITIQUE : Une session a été ouverte sur le système cible",
                "Le système est vulnérable à l'exploit utilisé",
                "Appliquez immédiatement les correctifs de sécurité appropriés",
                "Isolez le système compromis du réseau si possible"
            ])
        elif analysis['exploit_completed']:
            recommendations.extend([
                "⚠️ L'exploit s'est exécuté mais sans créer de session",
                "Le système pourrait être partiellement vulnérable",
                "Vérifiez les logs système pour détecter des anomalies"
            ])
        else:
            recommendations.extend([
                "Aucune exploitation réussie détectée",
                "Continuez à surveiller la sécurité du système"
            ])
        
        recommendations.extend([
            "Maintenez tous les systèmes à jour avec les derniers correctifs",
            "Implémentez une stratégie de défense en profondeur",
            "Surveillez les connexions réseau anormales",
            "Effectuez des tests de pénétration réguliers",
            "Formez les équipes aux bonnes pratiques de sécurité",
            "Configurez des systèmes de détection d'intrusion (IDS/IPS)"
        ])
        
        return recommendations


    def generate_wireshark_report(self, packets, wireshark_data):
        """Rapport spécialisé pour Wireshark avec analyse de trafic réseau"""
        filename = f"wireshark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("Wireshark", wireshark_data.get('capture_info', 'N/A')))
        
        # Titre section
        story.append(Paragraph("■ Analyse de Capture Réseau Wireshark", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Analyse du trafic
        traffic_analysis = self._analyze_wireshark_packets(packets)
        
        # Résumé de la capture
        summary_data = [
            ['Paramètre', 'Valeur'],
            ['🌐 Interface', wireshark_data.get('interface', 'N/A')],
            ['📊 Paquets capturés', str(len(packets))],
            ['🔍 Filtre appliqué', wireshark_data.get('filter', 'Aucun') or 'Aucun'],
            ['📅 Date de capture', datetime.now().strftime('%d/%m/%Y à %H:%M:%S')],
            ['⚡ Protocole principal', traffic_analysis['main_protocol']],
            ['🎯 Activité détectée', traffic_analysis['activity_level']]
        ]
        
        summary_table = Table(summary_data, colWidths=[150, 250])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Échantillon des paquets (premiers 15)
        story.append(Paragraph("📦 Échantillon des paquets capturés :", self.get_colored_style('#007bff', bold=True)))
        story.append(Spacer(1, 10))
        
        packet_data = [['#', 'Temps', 'Source → Destination', 'Protocole']]
        for packet in packets[:15]:
            packet_data.append([
                packet.get('num', '-'),
                packet.get('time', '-')[:8] + 's' if packet.get('time') else '-',
                f"{packet.get('source', '-')} → {packet.get('destination', '-')}",
                packet.get('protocol', '-')
            ])
        
        if len(packets) > 15:
            packet_data.append(['...', '...', f'... et {len(packets)-15} autres paquets', '...'])
        
        packet_table = Table(packet_data, colWidths=[30, 60, 200, 60])
        packet_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(packet_table)
        story.append(Spacer(1, 20))
        
        # Recommandations
        recommendations = self._get_wireshark_recommendations(traffic_analysis)
        story.append(Paragraph("💡 Recommandations d'analyse réseau :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 10))
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _analyze_wireshark_packets(self, packets):
        """Analyse les paquets Wireshark"""
        analysis = {
            'main_protocol': 'TCP',
            'activity_level': 'NORMALE',
            'protocol_stats': {},
            'top_communications': []
        }
        
        try:
            if not packets:
                return analysis
            
            # Compter les protocoles
            protocol_count = {}
            for packet in packets:
                protocol = packet.get('protocol', 'UNKNOWN')
                protocol_count[protocol] = protocol_count.get(protocol, 0) + 1
            
            # Protocole principal
            if protocol_count:
                analysis['main_protocol'] = max(protocol_count, key=protocol_count.get)
                analysis['protocol_stats'] = protocol_count
            
            # Niveau d'activité basé sur le nombre de paquets
            packet_count = len(packets)
            if packet_count > 50:
                analysis['activity_level'] = 'ÉLEVÉE'
            elif packet_count > 20:
                analysis['activity_level'] = 'MODÉRÉE'
            else:
                analysis['activity_level'] = 'FAIBLE'
                
        except Exception as e:
            print(f"[DEBUG] Erreur analyse Wireshark: {e}")
        
        return analysis

    def _get_wireshark_recommendations(self, analysis):
        """Recommandations basées sur l'analyse Wireshark"""
        recommendations = []
        
        if analysis['activity_level'] == 'ÉLEVÉE':
            recommendations.append("🔍 Activité réseau élevée détectée - Surveillez le trafic anormal")
        
        if 'HTTP' in analysis.get('protocol_stats', {}):
            recommendations.append("⚠️ Trafic HTTP détecté - Privilégiez HTTPS pour la sécurité")
        
        recommendations.extend([
            "📊 Analysez régulièrement le trafic réseau pour détecter les anomalies",
            "🔒 Surveillez les connexions vers des IPs externes inconnues",
            "🛡️ Implémentez une surveillance réseau continue (SIEM)",
            "📈 Documentez les patterns de trafic normal pour détecter les déviations",
            "🚨 Configurez des alertes pour les protocoles inhabituels",
            "🔍 Effectuez des analyses de trafic périodiques avec Wireshark"
        ])
        
        return recommendations


    def generate_zap_report(self, results_html, zap_data):
        """Rapport spécialisé pour OWASP ZAP avec analyse de vulnérabilités"""
        filename = f"zap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("OWASP ZAP", zap_data.get('target', 'N/A')))
        
        # Titre section
        story.append(Paragraph("■ Rapport de Sécurité OWASP ZAP", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Analyse des alertes ZAP
        zap_analysis = self._analyze_zap_alerts([])
        
        # Statut de sécurité
        if zap_analysis['critical_count'] > 0:
            status_text = "🚨 VULNÉRABILITÉS CRITIQUES DÉTECTÉES"
            status_color = '#dc3545'
            status_bg = colors.red
        elif zap_analysis['high_count'] > 0:
            status_text = "⚠️ VULNÉRABILITÉS ÉLEVÉES DÉTECTÉES"
            status_color = '#ff6b35'
            status_bg = colors.orange
        elif zap_analysis['medium_count'] > 0:
            status_text = "⚡ VULNÉRABILITÉS MOYENNES DÉTECTÉES"
            status_color = '#ffc107'
            status_bg = colors.yellow
        else:
            status_text = "✅ AUCUNE VULNÉRABILITÉ CRITIQUE DÉTECTÉE"
            status_color = '#28a745'
            status_bg = colors.green
        
        story.append(Paragraph(status_text, self.get_colored_style(status_color, bold=True, size=16)))
        story.append(Spacer(1, 15))
        
        # Résumé des vulnérabilités
        summary_data = [
            ['Métrique', 'Valeur'],
            ['🎯 URL analysée', zap_data.get('target', 'N/A')],
            ['🚨 Vulnérabilités critiques', str(zap_analysis['critical_count'])],
            ['⚠️ Vulnérabilités élevées', str(zap_analysis['high_count'])],
            ['⚡ Vulnérabilités moyennes', str(zap_analysis['medium_count'])],
            ['ℹ️ Vulnérabilités faibles', str(zap_analysis['low_count'])],
            ['📊 Total vulnérabilités', str(zap_analysis['total_count'])],
            ['📅 Date du scan', datetime.now().strftime('%d/%m/%Y à %H:%M:%S')]
        ]
        
        summary_table = Table(summary_data, colWidths=[180, 220])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), status_bg),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Top vulnérabilités critiques
        if zap_analysis['top_vulnerabilities']:
            story.append(Paragraph("🚨 Vulnérabilités prioritaires :", self.get_colored_style('#dc3545', bold=True)))
            story.append(Spacer(1, 10))
            
            vuln_data = [['Vulnérabilité', 'Risque', 'URL affectée']]
            for vuln in zap_analysis['top_vulnerabilities'][:10]:
                risk_color = self._get_risk_color(vuln['risk'])
                vuln_data.append([
                    vuln['name'][:40] + '...' if len(vuln['name']) > 40 else vuln['name'],
                    vuln['risk'],
                    vuln['url'][:40] + '...' if len(vuln['url']) > 40 else vuln['url']
                ])
            
            vuln_table = Table(vuln_data, colWidths=[200, 80, 120])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(vuln_table)
            story.append(Spacer(1, 20))
        
        # Catégories de vulnérabilités
        if zap_analysis['vulnerability_categories']:
            story.append(Paragraph("📊 Catégories de vulnérabilités :", self.get_colored_style('#007bff', bold=True)))
            story.append(Spacer(1, 10))
            
            cat_data = [['Catégorie', 'Occurrences']]
            for category, count in zap_analysis['vulnerability_categories'].items():
                cat_data.append([category, str(count)])
            
            cat_table = Table(cat_data, colWidths=[250, 100])
            cat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(cat_table)
            story.append(Spacer(1, 20))
        
        # Recommandations
        recommendations = self._get_zap_recommendations(zap_analysis)
        story.append(Paragraph("🛡️ Recommandations de sécurité prioritaires :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 10))
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _analyze_zap_alerts(self, alerts):
        """Analyse les alertes OWASP ZAP"""
        analysis = {
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'total_count': len(alerts),
            'top_vulnerabilities': [],
            'vulnerability_categories': {}
        }
        
        try:
            for alert in alerts:
                risk = alert.get('risk', 'Low')
                name = alert.get('alert', 'Unknown')
                url = alert.get('url', 'N/A')
                
                # Compter par niveau de risque
                if risk == 'High':
                    analysis['high_count'] += 1
                elif risk == 'Medium':
                    analysis['medium_count'] += 1
                elif risk == 'Low':
                    analysis['low_count'] += 1
                
                # Top vulnérabilités
                analysis['top_vulnerabilities'].append({
                    'name': name,
                    'risk': risk,
                    'url': url
                })
                
                # Catégories
                category = name.split(' ')[0]  # Premier mot comme catégorie
                analysis['vulnerability_categories'][category] = analysis['vulnerability_categories'].get(category, 0) + 1
            
            # Trier par risque
            risk_order = {'High': 3, 'Medium': 2, 'Low': 1}
            analysis['top_vulnerabilities'].sort(key=lambda x: risk_order.get(x['risk'], 0), reverse=True)
            
        except Exception as e:
            print(f"[DEBUG] Erreur analyse ZAP: {e}")
        
        return analysis

    def _get_risk_color(self, risk):
        """Retourne la couleur selon le niveau de risque"""
        if risk == 'High':
            return colors.red
        elif risk == 'Medium':
            return colors.orange
        elif risk == 'Low':
            return colors.yellow
        return colors.gray

    def _get_zap_recommendations(self, analysis):
        """Recommandations selon les vulnérabilités ZAP"""
        recommendations = []
        
        if analysis['high_count'] > 0:
            recommendations.extend([
                "🚨 URGENT : Corrigez immédiatement les vulnérabilités de niveau élevé",
                "Effectuez un audit de code approfondi",
                "Isolez l'application si elle est en production"
            ])
        
        if analysis['medium_count'] > 0:
            recommendations.append("⚡ Planifiez la correction des vulnérabilités moyennes dans les plus brefs délais")
        
        recommendations.extend([
            "🔒 Implémentez une validation stricte des entrées utilisateur",
            "🛡️ Configurez des en-têtes de sécurité appropriés (CSP, HSTS, X-Frame-Options)",
            "🔐 Utilisez HTTPS pour toutes les communications",
            "📊 Effectuez des scans ZAP réguliers",
            "🔄 Intégrez ZAP dans votre pipeline CI/CD",
            "👥 Formez l'équipe de développement aux bonnes pratiques OWASP",
            "📋 Suivez le guide OWASP Top 10 pour prévenir les vulnérabilités"
        ])
        
        return recommendations


    def generate_burpsuite_report(self, issues, burp_data):
        """Rapport spécialisé pour Burp Suite avec analyse de vulnérabilités"""
        filename = f"burpsuite_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("Burp Suite", burp_data.get('filename', 'Rapport importé')))
        
        # Titre section
        story.append(Paragraph("■ Analyse de Sécurité Burp Suite", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Analyse des issues Burp Suite
        burp_analysis = self._analyze_burpsuite_issues(issues)
        
        # Statut de sécurité
        if burp_analysis['high_count'] > 0:
            status_text = "🚨 VULNÉRABILITÉS CRITIQUES DÉTECTÉES"
            status_color = '#dc3545'
            status_bg = colors.red
        elif burp_analysis['medium_count'] > 0:
            status_text = "⚠️ VULNÉRABILITÉS MOYENNES DÉTECTÉES"
            status_color = '#ffc107'
            status_bg = colors.orange
        elif burp_analysis['low_count'] > 0:
            status_text = "ℹ️ VULNÉRABILITÉS FAIBLES DÉTECTÉES"
            status_color = '#17a2b8'
            status_bg = colors.blue
        else:
            status_text = "✅ AUCUNE VULNÉRABILITÉ DÉTECTÉE"
            status_color = '#28a745'
            status_bg = colors.green
        
        story.append(Paragraph(status_text, self.get_colored_style(status_color, bold=True, size=16)))
        story.append(Spacer(1, 15))
        
        # Résumé des vulnérabilités
        summary_data = [
            ['Métrique', 'Valeur'],
            ['📄 Fichier analysé', burp_data.get('filename', 'N/A')],
            ['🚨 Vulnérabilités élevées', str(burp_analysis['high_count'])],
            ['⚠️ Vulnérabilités moyennes', str(burp_analysis['medium_count'])],
            ['ℹ️ Vulnérabilités faibles', str(burp_analysis['low_count'])],
            ['📊 Total vulnérabilités', str(burp_analysis['total_count'])],
            ['🎯 Hosts affectés', str(len(burp_analysis['affected_hosts']))],
            ['📅 Date d\'analyse', datetime.now().strftime('%d/%m/%Y à %H:%M:%S')]
        ]
        
        summary_table = Table(summary_data, colWidths=[180, 220])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), status_bg),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Top vulnérabilités critiques
        if burp_analysis['top_issues']:
            story.append(Paragraph("🚨 Vulnérabilités prioritaires :", self.get_colored_style('#dc3545', bold=True)))
            story.append(Spacer(1, 10))
            
            vuln_data = [['Vulnérabilité', 'Gravité', 'Host']]
            for issue in burp_analysis['top_issues'][:10]:
                severity_color = self._get_burp_severity_color(issue['severity'])
                vuln_data.append([
                    issue['name'][:50] + '...' if len(issue['name']) > 50 else issue['name'],
                    issue['severity'],
                    issue['host'][:30] + '...' if len(issue['host']) > 30 else issue['host']
                ])
            
            vuln_table = Table(vuln_data, colWidths=[200, 80, 120])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(vuln_table)
            story.append(Spacer(1, 20))
        
        # Catégories de vulnérabilités
        if burp_analysis['issue_categories']:
            story.append(Paragraph("📊 Catégories de vulnérabilités :", self.get_colored_style('#007bff', bold=True)))
            story.append(Spacer(1, 10))
            
            cat_data = [['Catégorie', 'Occurrences']]
            for category, count in list(burp_analysis['issue_categories'].items())[:10]:
                cat_data.append([category[:40] + '...' if len(category) > 40 else category, str(count)])
            
            cat_table = Table(cat_data, colWidths=[300, 100])
            cat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(cat_table)
            story.append(Spacer(1, 20))
        
        # Hosts affectés
        if burp_analysis['affected_hosts']:
            story.append(Paragraph("🎯 Hosts affectés :", self.get_colored_style('#ffc107', bold=True)))
            story.append(Spacer(1, 10))
            
            hosts_text = ""
            for host in list(burp_analysis['affected_hosts'])[:10]:
                hosts_text += f"• {host}\n"
            
            if len(burp_analysis['affected_hosts']) > 10:
                hosts_text += f"... et {len(burp_analysis['affected_hosts']) - 10} autres hosts"
            
            story.append(Paragraph(hosts_text.replace('\n', '<br/>'), self.styles['normal']))
            story.append(Spacer(1, 20))
        
        # Recommandations
        recommendations = self._get_burpsuite_recommendations(burp_analysis)
        story.append(Paragraph("🛡️ Recommandations de sécurité prioritaires :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 10))
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _analyze_burpsuite_issues(self, issues):
        """Analyse les issues Burp Suite"""
        analysis = {
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'info_count': 0,
            'total_count': len(issues),
            'top_issues': [],
            'issue_categories': {},
            'affected_hosts': set()
        }
        
        try:
            for issue in issues:
                # Extraire les données selon le format XML ou HTML
                name_elem = issue.find('name') or issue.find('td', class_='name')
                severity_elem = issue.find('severity') or issue.find('td', class_='severity')
                host_elem = issue.find('host') or issue.find('td', class_='host')
                
                name = name_elem.text.strip() if name_elem else 'Vulnérabilité inconnue'
                severity = severity_elem.text.strip() if severity_elem else 'Low'
                host = host_elem.text.strip() if host_elem else 'Inconnu'
                
                # Compter par sévérité
                if severity == 'High':
                    analysis['high_count'] += 1
                elif severity == 'Medium':
                    analysis['medium_count'] += 1
                elif severity == 'Low':
                    analysis['low_count'] += 1
                else:
                    analysis['info_count'] += 1
                
                # Top issues
                analysis['top_issues'].append({
                    'name': name,
                    'severity': severity,
                    'host': host
                })
                
                # Catégories
                analysis['issue_categories'][name] = analysis['issue_categories'].get(name, 0) + 1
                
                # Hosts affectés
                if host and host != 'Inconnu':
                    analysis['affected_hosts'].add(host)
            
            # Trier par sévérité
            severity_order = {'High': 4, 'Medium': 3, 'Low': 2, 'Information': 1}
            analysis['top_issues'].sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
            
        except Exception as e:
            print(f"[DEBUG] Erreur analyse Burp Suite: {e}")
        
        return analysis

    def _get_burp_severity_color(self, severity):
        """Retourne la couleur selon la sévérité Burp Suite"""
        if severity == 'High':
            return colors.red
        elif severity == 'Medium':
            return colors.orange
        elif severity == 'Low':
            return colors.yellow
        return colors.gray

    def _get_burpsuite_recommendations(self, analysis):
        """Recommandations selon les vulnérabilités Burp Suite"""
        recommendations = []
        
        if analysis['high_count'] > 0:
            recommendations.extend([
                "🚨 URGENT : Corrigez immédiatement les vulnérabilités de niveau élevé",
                "Isolez les applications vulnérables si elles sont en production",
                "Effectuez un audit de code approfondi"
            ])
        
        if analysis['medium_count'] > 0:
            recommendations.append("⚠️ Planifiez la correction des vulnérabilités moyennes rapidement")
        
        recommendations.extend([
            "🔒 Implémentez une validation stricte des entrées utilisateur",
            "🛡️ Configurez des en-têtes de sécurité appropriés",
            "🔐 Utilisez HTTPS pour toutes les communications sensibles",
            "📊 Intégrez Burp Suite dans vos tests de sécurité réguliers",
            "🔄 Effectuez des scans automatisés dans votre pipeline CI/CD",
            "👥 Formez l'équipe de développement aux vulnérabilités web OWASP",
            "📋 Implémentez une politique de développement sécurisé",
            "🔍 Effectuez des tests de pénétration réguliers"
        ])
        
        return recommendations

    def generate_wapiti_report(self, results, wapiti_data):
        """Rapport spécialisé pour Wapiti avec analyse de vulnérabilités"""
        filename = f"wapiti_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("Wapiti", wapiti_data.get('url', 'N/A')))
        
        # Titre section
        story.append(Paragraph("■ Rapport de Sécurité Web Wapiti", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Analyse des résultats Wapiti
        wapiti_analysis = self._analyze_wapiti_results(results)
        
        # Statut de sécurité
        if wapiti_analysis['vulnerabilities_found'] > 0:
            status_text = "🚨 VULNÉRABILITÉS WEB DÉTECTÉES"
            status_color = '#dc3545'
            status_bg = colors.red
        elif wapiti_analysis['warnings_found'] > 0:
            status_text = "⚠️ AVERTISSEMENTS DÉTECTÉS"
            status_color = '#ffc107'
            status_bg = colors.orange
        else:
            status_text = "✅ AUCUNE VULNÉRABILITÉ CRITIQUE DÉTECTÉE"
            status_color = '#28a745'
            status_bg = colors.green
        
        story.append(Paragraph(status_text, self.get_colored_style(status_color, bold=True, size=16)))
        story.append(Spacer(1, 15))
        
        # Résumé du scan
        summary_data = [
            ['Métrique', 'Valeur'],
            ['🎯 URL scannée', wapiti_data.get('url', 'N/A')],
            ['🚨 Vulnérabilités trouvées', str(wapiti_analysis['vulnerabilities_found'])],
            ['⚠️ Avertissements', str(wapiti_analysis['warnings_found'])],
            ['📊 Pages analysées', str(wapiti_analysis['pages_scanned'])],
            ['🔍 Type de scan', wapiti_analysis['scan_type']],
            ['📅 Date du scan', datetime.now().strftime('%d/%m/%Y à %H:%M:%S')]
        ]
        
        summary_table = Table(summary_data, colWidths=[180, 220])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), status_bg),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Vulnérabilités détectées
        if wapiti_analysis['vulnerability_types']:
            story.append(Paragraph("🚨 Types de vulnérabilités détectées :", self.get_colored_style('#dc3545', bold=True)))
            story.append(Spacer(1, 10))
            
            vuln_data = [['Type de vulnérabilité', 'Occurrences', 'Criticité']]
            for vuln_type, count in wapiti_analysis['vulnerability_types'].items():
                criticite = self._get_wapiti_criticality(vuln_type)
                vuln_data.append([vuln_type, str(count), criticite])
            
            vuln_table = Table(vuln_data, colWidths=[200, 80, 120])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)
            story.append(Spacer(1, 20))
        
        # URLs affectées
        if wapiti_analysis['affected_urls']:
            story.append(Paragraph("🎯 URLs affectées :", self.get_colored_style('#ffc107', bold=True)))
            story.append(Spacer(1, 10))
            
            urls_text = ""
            for url in wapiti_analysis['affected_urls'][:10]:
                urls_text += f"• {url}\n"
            
            if len(wapiti_analysis['affected_urls']) > 10:
                urls_text += f"... et {len(wapiti_analysis['affected_urls']) - 10} autres URLs"
            
            story.append(Paragraph(urls_text.replace('\n', '<br/>'), self.styles['normal']))
            story.append(Spacer(1, 20))
        
        # Extrait du rapport technique
        story.append(Paragraph("🔍 Extrait du rapport technique :", self.get_colored_style('#007bff', bold=True)))
        story.append(Spacer(1, 10))
        
        # Nettoyer et formater les résultats
        cleaned_results = self._clean_wapiti_output(results)
        story.append(Paragraph(f"<font name='Courier' size='7'>{cleaned_results}</font>", self.styles['normal']))
        story.append(Spacer(1, 20))
        
        # Recommandations
        recommendations = self._get_wapiti_recommendations(wapiti_analysis)
        story.append(Paragraph("🛡️ Recommandations de sécurité web :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 10))
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _analyze_wapiti_results(self, results):
        """Analyse les résultats Wapiti"""
        import re
        
        analysis = {
            'vulnerabilities_found': 0,
            'warnings_found': 0,
            'pages_scanned': 0,
            'scan_type': 'Scan web complet',
            'vulnerability_types': {},
            'affected_urls': []
        }
        
        try:
            # Compter les vulnérabilités
            vuln_patterns = [
                r'vulnerability|vuln',
                r'injection|xss|sql',
                r'csrf|rfi|lfi',
                r'security|exploit'
            ]
            
            for pattern in vuln_patterns:
                matches = re.findall(pattern, results, re.IGNORECASE)
                analysis['vulnerabilities_found'] += len(matches)
            
            # Compter les avertissements
            warning_patterns = ['warning', 'potential', 'possible', 'suspicious']
            for pattern in warning_patterns:
                matches = re.findall(pattern, results, re.IGNORECASE)
                analysis['warnings_found'] += len(matches)
            
            # Extraire types de vulnérabilités
            if 'xss' in results.lower():
                analysis['vulnerability_types']['Cross-Site Scripting (XSS)'] = results.lower().count('xss')
            if 'sql' in results.lower():
                analysis['vulnerability_types']['SQL Injection'] = results.lower().count('sql')
            if 'csrf' in results.lower():
                analysis['vulnerability_types']['Cross-Site Request Forgery'] = results.lower().count('csrf')
            if 'lfi' in results.lower() or 'rfi' in results.lower():
                analysis['vulnerability_types']['File Inclusion'] = results.lower().count('lfi') + results.lower().count('rfi')
            
            # Extraire URLs
            url_matches = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', results)
            analysis['affected_urls'] = list(set(url_matches))[:20]  # Max 20 URLs uniques
            
            # Estimer pages scannées
            if 'page' in results.lower():
                page_matches = re.findall(r'(\d+)\s*page', results, re.IGNORECASE)
                if page_matches:
                    analysis['pages_scanned'] = int(page_matches[-1])
                else:
                    analysis['pages_scanned'] = len(analysis['affected_urls'])
            
        except Exception as e:
            print(f"[DEBUG] Erreur analyse Wapiti: {e}")
        
        return analysis

    def _get_wapiti_criticality(self, vuln_type):
        """Retourne la criticité selon le type de vulnérabilité"""
        critical_vulns = ['SQL Injection', 'Cross-Site Scripting (XSS)']
        medium_vulns = ['Cross-Site Request Forgery', 'File Inclusion']
        
        if vuln_type in critical_vulns:
            return 'CRITIQUE'
        elif vuln_type in medium_vulns:
            return 'MOYENNE'
        return 'FAIBLE'

    def _clean_wapiti_output(self, results):
        """Nettoie la sortie Wapiti pour le PDF"""
        import re
        
        # Prendre les parties importantes
        lines = results.split('\n')
        important_lines = []
        
        for line in lines[:40]:
            if any(keyword in line.lower() for keyword in 
                   ['vulnerability', 'found', 'target', 'scan', 'warning', 'error']):
                important_lines.append(line.strip())
        
        if len(important_lines) < 15:
            important_lines = lines[:25]
        
        cleaned = '\n'.join(important_lines)
        cleaned = re.sub(r'[^\x20-\x7E\n]', '', cleaned)
        cleaned = cleaned.replace('\n', '<br/>')
        
        if len(cleaned) > 2000:
            cleaned = cleaned[:2000] + '<br/>[... Log tronqué pour le PDF ...]'
        
        return cleaned

    def _get_wapiti_recommendations(self, analysis):
        """Recommandations selon les vulnérabilités Wapiti"""
        recommendations = []
        
        if analysis['vulnerabilities_found'] > 0:
            recommendations.extend([
                "🚨 URGENT : Corrigez les vulnérabilités web détectées",
                "Validez et échappez toutes les entrées utilisateur",
                "Implémentez une protection CSRF appropriée"
            ])
        
        if 'Cross-Site Scripting (XSS)' in analysis['vulnerability_types']:
            recommendations.append("🔒 Implémentez une politique CSP (Content Security Policy) stricte")
        
        if 'SQL Injection' in analysis['vulnerability_types']:
            recommendations.append("💉 Utilisez des requêtes préparées pour toutes les interactions avec la base de données")
        
        recommendations.extend([
            "🛡️ Configurez des en-têtes de sécurité appropriés",
            "🔐 Utilisez HTTPS pour toutes les communications",
            "📊 Effectuez des scans Wapiti réguliers",
            "🔄 Intégrez Wapiti dans votre pipeline CI/CD",
            "👥 Formez l'équipe aux vulnérabilités web OWASP Top 10",
            "📋 Implémentez un processus de développement sécurisé",
            "🔍 Effectuez des tests de pénétration périodiques"
        ])
        
        return recommendations

    def generate_ettercap_report(self, results, ettercap_data):
        """Rapport spécialisé pour Ettercap avec analyse d'attaque MITM"""
        filename = f"ettercap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("Ettercap MITM", ettercap_data.get('attack_info', 'N/A')))
        
        # Titre section
        story.append(Paragraph("Rapport d'Attaque Man-in-the-Middle", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Analyse des résultats Ettercap
        ettercap_analysis = self._analyze_ettercap_results(results, ettercap_data.get('captured_data', {}))
        
        # Statut de l'attaque
        if ettercap_analysis['mitm_successful']:
            status_text = "ATTAQUE MITM REUSSIE - TRAFIC INTERCEPTE"
            status_color = '#dc3545'
            status_bg = colors.red
        elif ettercap_analysis['simulation_mode']:
            status_text = "MODE SIMULATION - ATTAQUE MITM SIMULEE"
            status_color = '#ffc107'
            status_bg = colors.orange
        else:
            status_text = "ECHEC DE L'ATTAQUE MITM"
            status_color = '#6c757d'
            status_bg = colors.gray
        
        story.append(Paragraph(status_text, self.get_colored_style(status_color, bold=True, size=16)))
        story.append(Spacer(1, 15))
        
        # Résumé de l'attaque
        summary_data = [
            ['Parametre', 'Valeur'],
            ['Configuration', ettercap_data.get('attack_info', 'N/A')],
            ['Paquets interceptes', str(ettercap_analysis['total_packets'])],
            ['Paquets HTTP', str(ettercap_analysis['http_packets'])],
            ['Paquets HTTPS', str(ettercap_analysis['https_packets'])],
            ['Requetes DNS', str(ettercap_analysis['dns_packets'])],
            ['Type attaque', ettercap_analysis['attack_type']],
            ['Date attaque', datetime.now().strftime('%d/%m/%Y à %H:%M:%S')]
        ]
        
        summary_table = Table(summary_data, colWidths=[180, 220])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), status_bg),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Informations de la cible
        if ettercap_analysis['target_detected']:
            story.append(Paragraph("Informations de la cible :", self.get_colored_style('#dc3545', bold=True)))
            story.append(Spacer(1, 10))
            
            target_data = [['Propriete', 'Valeur']]
            target_info = ettercap_analysis['target_info']
            for key, value in target_info.items():
                if value and value != 'N/A':
                    target_data.append([key.upper(), str(value)])
            
            target_table = Table(target_data, colWidths=[150, 250])
            target_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(target_table)
            story.append(Spacer(1, 20))
        
        # Paquets interceptés détaillés
        if ettercap_analysis['intercepted_packets']:
            story.append(Paragraph("Detail des paquets interceptes :", self.get_colored_style('#007bff', bold=True)))
            story.append(Spacer(1, 10))
            
            packet_data = [['Heure', 'Protocole', 'Source -> Destination', 'Information']]
            for packet in ettercap_analysis['intercepted_packets'][:15]:
                packet_data.append([
                    packet.get('timestamp', '-'),
                    packet.get('protocol', '-'),
                    f"{packet.get('source', '-')} -> {packet.get('destination', '-')}",
                    packet.get('info', '-')[:50] + '...' if len(packet.get('info', '')) > 50 else packet.get('info', '-')
                ])
            
            if len(ettercap_analysis['intercepted_packets']) > 15:
                packet_data.append(['...', '...', '...', f'... et {len(ettercap_analysis["intercepted_packets"]) - 15} autres paquets'])
            
            packet_table = Table(packet_data, colWidths=[60, 60, 140, 140])
            packet_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(packet_table)
            story.append(Spacer(1, 20))
        
        # Log technique
        story.append(Paragraph("Extrait du log technique :", self.get_colored_style('#6c757d', bold=True)))
        story.append(Spacer(1, 10))
        
        # Nettoyer et formater les résultats
        cleaned_results = self._clean_ettercap_output(results)
        story.append(Paragraph(f"<font name='Courier' size='7'>{cleaned_results}</font>", self.styles['normal']))
        story.append(Spacer(1, 20))
        
        # Recommandations
        recommendations = self._get_ettercap_recommendations(ettercap_analysis)
        story.append(Paragraph("Recommandations de securite reseau :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 10))
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _analyze_ettercap_results(self, results, captured_data):
        """Analyse les résultats d'une attaque Ettercap"""
        analysis = {
            'mitm_successful': False,
            'simulation_mode': False,
            'target_detected': False,
            'total_packets': 0,
            'http_packets': 0,
            'https_packets': 0,
            'dns_packets': 0,
            'attack_type': 'ARP Spoofing',
            'target_info': {},
            'intercepted_packets': [],
            'protocol_analysis': {}
        }
        
        try:
            # Détecter le mode simulation
            if 'simulation' in results.lower() or 'simule' in results.lower():
                analysis['simulation_mode'] = True
                analysis['mitm_successful'] = True
            
            # Détecter succès MITM réel
            if 'arp poisoning' in results.lower() and 'actif' in results.lower():
                analysis['mitm_successful'] = True
            
            # Analyser les données capturées
            if captured_data:
                # Informations de la cible
                if 'target_info' in captured_data:
                    analysis['target_detected'] = True
                    analysis['target_info'] = captured_data['target_info']
                
                # Statistiques des paquets
                if 'statistics' in captured_data:
                    stats = captured_data['statistics']
                    analysis['total_packets'] = stats.get('total_packets', 0)
                    analysis['http_packets'] = stats.get('http_packets', 0)
                    analysis['https_packets'] = stats.get('https_packets', 0)
                    analysis['dns_packets'] = stats.get('dns_packets', 0)
                
                # Paquets interceptés
                if 'intercepted_packets' in captured_data:
                    analysis['intercepted_packets'] = captured_data['intercepted_packets']
                    
                    # Analyse des protocoles
                    for packet in analysis['intercepted_packets']:
                        protocol = packet.get('protocol', 'UNKNOWN')
                        analysis['protocol_analysis'][protocol] = analysis['protocol_analysis'].get(protocol, 0) + 1
            
        except Exception as e:
            print(f"[DEBUG] Erreur analyse Ettercap: {e}")
        
        return analysis

    def _clean_ettercap_output(self, results):
        """Nettoie la sortie Ettercap pour le PDF"""
        import re
        
        # Prendre les parties importantes
        lines = results.split('\n')
        important_lines = []
        
        for line in lines[:30]:
            if any(keyword in line.lower() for keyword in 
                   ['arp', 'poisoning', 'target', 'group', 'interface', 'attaque', 'mitm', 'scan']):
                important_lines.append(line.strip())
        
        if len(important_lines) < 10:
            important_lines = lines[:20]
        
        cleaned = '\n'.join(important_lines)
        cleaned = re.sub(r'[^\x20-\x7E\n]', '', cleaned)
        cleaned = cleaned.replace('\n', '<br/>')
        
        if len(cleaned) > 2000:
            cleaned = cleaned[:2000] + '<br/>[... Log tronque pour le PDF ...]'
        
        return cleaned

    def _get_ettercap_recommendations(self, analysis):
        """Recommandations selon les résultats Ettercap"""
        recommendations = []
        
        if analysis['mitm_successful']:
            if analysis['simulation_mode']:
                recommendations.extend([
                    "Test de simulation reussi - Votre reseau est vulnerable aux attaques MITM",
                    "Implementez une protection contre l'ARP spoofing",
                    "Configurez la securite des commutateurs (Port Security)"
                ])
            else:
                recommendations.extend([
                    "CRITIQUE : Attaque MITM reelle reussie sur votre reseau",
                    "URGENT : Isolez immediatement le reseau compromis",
                    "Verifiez tous les equipements reseau pour detecter d'autres attaques"
                ])
        
        if analysis['http_packets'] > 0:
            recommendations.append("Trafic HTTP non chiffre detecte - Migrez vers HTTPS")
        
        if analysis['dns_packets'] > 0:
            recommendations.append("Requetes DNS interceptees - Utilisez DNS over HTTPS (DoH)")
        
        recommendations.extend([
            "Configurez des tables ARP statiques pour les serveurs critiques",
            "Implementez une surveillance reseau continue (IDS/IPS)",
            "Utilisez des certificats TLS pour authentifier les communications",
            "Configurez VLAN pour segmenter le reseau",
            "Formez les equipes a detecter les attaques MITM",
            "Effectuez des tests de penetration reguliers",
            "Installez des systemes de detection d'ARP spoofing",
            "Implementez une politique de securite reseau stricte"
        ])
        
        return recommendations

    def generate_nmap_report(self, results, nmap_data):
        """Rapport spécialisé pour Nmap avec analyse des ports et services"""
        filename = f"nmap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("Nmap", nmap_data.get('target', 'N/A')))
        
        # Titre section
        story.append(Paragraph("■ Rapport de Scan Réseau Nmap", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Analyse des résultats Nmap
        nmap_analysis = self._analyze_nmap_results(results)
        
        # Statut de sécurité
        if nmap_analysis['critical_ports'] > 0:
            status_text = "🚨 PORTS CRITIQUES OUVERTS DÉTECTÉS"
            status_color = '#dc3545'
            status_bg = colors.red
        elif nmap_analysis['total_open_ports'] > 10:
            status_text = "⚠️ NOMBREUX PORTS OUVERTS DÉTECTÉS"
            status_color = '#ffc107'
            status_bg = colors.orange
        elif nmap_analysis['total_open_ports'] > 0:
            status_text = "ℹ️ PORTS OUVERTS DÉTECTÉS"
            status_color = '#17a2b8'
            status_bg = colors.blue
        else:
            status_text = "✅ AUCUN PORT OUVERT DÉTECTÉ"
            status_color = '#28a745'
            status_bg = colors.green
        
        story.append(Paragraph(status_text, self.get_colored_style(status_color, bold=True, size=16)))
        story.append(Spacer(1, 15))
        
        # Résumé du scan
        summary_data = [
            ['Métrique', 'Valeur'],
            ['🎯 Cible scannée', nmap_data.get('target', 'N/A')],
            ['🔍 Type de scan', nmap_data.get('scan_type', 'Standard')],
            ['🚪 Ports ouverts', str(nmap_analysis['total_open_ports'])],
            ['⚠️ Ports critiques', str(nmap_analysis['critical_ports'])],
            ['🔒 Ports fermés', str(nmap_analysis['closed_ports'])],
            ['🛡️ Services détectés', str(len(nmap_analysis['services']))],
            ['📅 Date du scan', datetime.now().strftime('%d/%m/%Y à %H:%M:%S')]
        ]
        
        summary_table = Table(summary_data, colWidths=[180, 220])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), status_bg),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Ports ouverts détaillés
        if nmap_analysis['open_ports']:
            story.append(Paragraph("🚪 Ports ouverts détectés :", self.get_colored_style('#dc3545', bold=True)))
            story.append(Spacer(1, 10))
            
            ports_data = [['Port', 'Protocole', 'Service', 'Version', 'Risque']]
            for port_info in nmap_analysis['open_ports'][:15]:
                risk_level = self._get_port_risk_level(port_info['port'])
                ports_data.append([
                    str(port_info['port']),
                    port_info['protocol'],
                    port_info['service'],
                    port_info['version'][:30] + '...' if len(port_info['version']) > 30 else port_info['version'],
                    risk_level
                ])
            
            if len(nmap_analysis['open_ports']) > 15:
                ports_data.append(['...', '...', '...', f'... et {len(nmap_analysis["open_ports"]) - 15} autres ports', '...'])
            
            ports_table = Table(ports_data, colWidths=[50, 60, 80, 120, 80])
            ports_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(ports_table)
            story.append(Spacer(1, 20))
        
        # Services détectés
        if nmap_analysis['services']:
            story.append(Paragraph("🛡️ Services identifiés :", self.get_colored_style('#007bff', bold=True)))
            story.append(Spacer(1, 10))
            
            services_data = [['Service', 'Occurrences', 'Ports associés']]
            for service, info in list(nmap_analysis['services'].items())[:10]:
                ports_list = ', '.join(map(str, info['ports'][:5]))
                if len(info['ports']) > 5:
                    ports_list += f" (+{len(info['ports'])-5})"
                
                services_data.append([
                    service,
                    str(info['count']),
                    ports_list
                ])
            
            services_table = Table(services_data, colWidths=[120, 80, 200])
            services_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(services_table)
            story.append(Spacer(1, 20))
        
        # Informations système
        if nmap_analysis['system_info']:
            story.append(Paragraph("💻 Informations système :", self.get_colored_style('#28a745', bold=True)))
            story.append(Spacer(1, 10))
            
            sys_data = [['Propriété', 'Valeur']]
            for key, value in nmap_analysis['system_info'].items():
                sys_data.append([key, value])
            
            sys_table = Table(sys_data, colWidths=[150, 250])
            sys_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(sys_table)
            story.append(Spacer(1, 20))
        
        # Log technique
        story.append(Paragraph("🔍 Extrait du scan technique :", self.get_colored_style('#6c757d', bold=True)))
        story.append(Spacer(1, 10))
        
        # Nettoyer et formater les résultats
        cleaned_results = self._clean_nmap_output(results)
        story.append(Paragraph(f"<font name='Courier' size='7'>{cleaned_results}</font>", self.styles['normal']))
        story.append(Spacer(1, 20))
        
        # Recommandations
        recommendations = self._get_nmap_recommendations(nmap_analysis)
        story.append(Paragraph("🛡️ Recommandations de sécurité réseau :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 10))
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _analyze_nmap_results(self, results):
        """Analyse les résultats d'un scan Nmap"""
        import re
        
        analysis = {
            'total_open_ports': 0,
            'critical_ports': 0,
            'closed_ports': 0,
            'open_ports': [],
            'services': {},
            'system_info': {}
        }
        
        try:
            lines = results.split('\n')
            
            for line in lines:
                # Détecter ports ouverts
                port_match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?', line)
                if port_match:
                    port_num = int(port_match.group(1))
                    protocol = port_match.group(2)
                    service = port_match.group(3)
                    version = port_match.group(4) or 'Version non détectée'
                    
                    analysis['total_open_ports'] += 1
                    
                    # Identifier ports critiques
                    if port_num in [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389]:
                        analysis['critical_ports'] += 1
                    
                    # Ajouter à la liste des ports ouverts
                    analysis['open_ports'].append({
                        'port': port_num,
                        'protocol': protocol,
                        'service': service,
                        'version': version
                    })
                    
                    # Compter les services
                    if service not in analysis['services']:
                        analysis['services'][service] = {'count': 0, 'ports': []}
                    analysis['services'][service]['count'] += 1
                    analysis['services'][service]['ports'].append(port_num)
                
                # Détecter ports fermés
                elif 'closed' in line and 'tcp' in line:
                    analysis['closed_ports'] += 1
                
                # Détecter informations système
                elif 'Running:' in line:
                    analysis['system_info']['OS'] = line.split('Running:')[1].strip()
                elif 'Device type:' in line:
                    analysis['system_info']['Type appareil'] = line.split('Device type:')[1].strip()
                elif 'MAC Address:' in line:
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if mac_match:
                        analysis['system_info']['Adresse MAC'] = mac_match.group(0)
                elif 'Network Distance:' in line:
                    analysis['system_info']['Distance réseau'] = line.split('Network Distance:')[1].strip()
                elif 'latency' in line.lower():
                    latency_match = re.search(r'(\d+\.\d+)s latency', line)
                    if latency_match:
                        analysis['system_info']['Latence'] = latency_match.group(1) + 's'
            
        except Exception as e:
            print(f"[DEBUG] Erreur analyse Nmap: {e}")
        
        return analysis

    def _get_port_risk_level(self, port):
        """Retourne le niveau de risque selon le port"""
        critical_ports = [21, 23, 135, 139, 445, 3389]  # FTP, Telnet, RPC, NetBIOS, SMB, RDP
        high_risk_ports = [22, 25, 53, 80, 443, 993, 995]  # SSH, SMTP, DNS, HTTP, HTTPS, IMAPS, POP3S
        
        if port in critical_ports:
            return 'CRITIQUE'
        elif port in high_risk_ports:
            return 'ÉLEVÉ'
        elif port < 1024:
            return 'MOYEN'
        return 'FAIBLE'

    def _clean_nmap_output(self, results):
        """Nettoie la sortie Nmap pour le PDF"""
        import re
        
        # Prendre les parties importantes
        lines = results.split('\n')
        important_lines = []
        
        for line in lines[:30]:
            if any(keyword in line.lower() for keyword in 
                   ['nmap scan', 'host is up', 'port', 'open', 'service', 'version', 'os', 'mac']):
                important_lines.append(line.strip())
        
        if len(important_lines) < 15:
            important_lines = lines[:25]
        
        cleaned = '\n'.join(important_lines)
        cleaned = re.sub(r'[^\x20-\x7E\n]', '', cleaned)
        cleaned = cleaned.replace('\n', '<br/>')
        
        if len(cleaned) > 2000:
            cleaned = cleaned[:2000] + '<br/>[... Log tronqué pour le PDF ...]'
        
        return cleaned

    def _get_nmap_recommendations(self, analysis):
        """Recommandations selon les résultats Nmap"""
        recommendations = []
        
        if analysis['critical_ports'] > 0:
            recommendations.extend([
                "🚨 CRITIQUE : Des ports à haut risque sont ouverts",
                "Fermez les ports non nécessaires (Telnet, FTP, NetBIOS, SMB)",
                "Renforcez l'authentification sur les services exposés"
            ])
        
        if analysis['total_open_ports'] > 10:
            recommendations.append("⚠️ Nombreux ports ouverts - Appliquez le principe du moindre privilège")
        
        # Recommandations par service
        services = analysis.get('services', {})
        if 'ssh' in services:
            recommendations.append("🔑 SSH détecté - Utilisez l'authentification par clés et désactivez root")
        if 'http' in services:
            recommendations.append("🔒 HTTP détecté - Migrez vers HTTPS avec certificats valides")
        if 'ftp' in services:
            recommendations.append("📁 FTP détecté - Remplacez par SFTP ou FTPS")
        
        recommendations.extend([
            "🛡️ Configurez un pare-feu pour filtrer le trafic entrant",
            "📊 Surveillez régulièrement les ports ouverts avec Nmap",
            "🔄 Effectuez des scans périodiques pour détecter les changements",
            "👥 Formez les équipes aux bonnes pratiques de sécurité réseau",
            "📋 Documentez et justifiez chaque port ouvert",
            "🔍 Implémentez une surveillance réseau continue (SIEM)",
            "⚡ Mettez à jour régulièrement les services exposés"
        ])
        
        return recommendations

    def generate_sslyze_report(self, results, sslyze_data):
        """Rapport spécialisé pour SSLyze avec analyse SSL/TLS"""
        filename = f"sslyze_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=20, bottomMargin=20)
        story = []
        
        # Header
        story.extend(self._create_header("SSLyze", sslyze_data.get('target', 'N/A')))
        
        # Titre section
        story.append(Paragraph("■ Rapport d'Analyse SSL/TLS SSLyze", self.styles['section_title']))
        story.append(Spacer(1, 10))
        
        # Analyse des résultats SSLyze
        sslyze_analysis = self._analyze_sslyze_results(results)
        
        # Statut de sécurité SSL
        if sslyze_analysis['critical_issues'] > 0:
            status_text = "🚨 PROBLÈMES CRITIQUES SSL/TLS DÉTECTÉS"
            status_color = '#dc3545'
            status_bg = colors.red
        elif sslyze_analysis['warnings'] > 0:
            status_text = "⚠️ AVERTISSEMENTS SSL/TLS DÉTECTÉS"
            status_color = '#ffc107'
            status_bg = colors.orange
        elif sslyze_analysis['ssl_configured']:
            status_text = "✅ CONFIGURATION SSL/TLS SÉCURISÉE"
            status_color = '#28a745'
            status_bg = colors.green
        else:
            status_text = "❌ SSL/TLS NON CONFIGURÉ OU INACCESSIBLE"
            status_color = '#6c757d'
            status_bg = colors.gray
        
        story.append(Paragraph(status_text, self.get_colored_style(status_color, bold=True, size=16)))
        story.append(Spacer(1, 15))
        
        # Résumé de l'analyse
        summary_data = [
            ['Métrique', 'Valeur'],
            ['🎯 Domaine analysé', sslyze_data.get('domain', 'N/A')],
            ['🔒 SSL/TLS configuré', 'Oui' if sslyze_analysis['ssl_configured'] else 'Non'],
            ['🚨 Problèmes critiques', str(sslyze_analysis['critical_issues'])],
            ['⚠️ Avertissements', str(sslyze_analysis['warnings'])],
            ['🔑 Certificat valide', 'Oui' if sslyze_analysis['cert_valid'] else 'Non'],
            ['🛡️ Protocoles supportés', str(len(sslyze_analysis['protocols']))],
            ['📅 Date d\'analyse', datetime.now().strftime('%d/%m/%Y à %H:%M:%S')]
        ]
        
        summary_table = Table(summary_data, colWidths=[180, 220])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), status_bg),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Protocoles SSL/TLS supportés
        if sslyze_analysis['protocols']:
            story.append(Paragraph("🔒 Protocoles SSL/TLS supportés :", self.get_colored_style('#007bff', bold=True)))
            story.append(Spacer(1, 10))
            
            protocol_data = [['Protocole', 'Statut', 'Sécurité']]
            for protocol, status in sslyze_analysis['protocols'].items():
                security_level = self._get_ssl_security_level(protocol)
                protocol_data.append([protocol, status, security_level])
            
            protocol_table = Table(protocol_data, colWidths=[120, 120, 160])
            protocol_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(protocol_table)
            story.append(Spacer(1, 20))
        
        # Informations du certificat
        if sslyze_analysis['certificate_info']:
            story.append(Paragraph("📜 Informations du certificat :", self.get_colored_style('#28a745', bold=True)))
            story.append(Spacer(1, 10))
            
            cert_data = [['Propriété', 'Valeur']]
            for key, value in sslyze_analysis['certificate_info'].items():
                cert_data.append([key, value])
            
            cert_table = Table(cert_data, colWidths=[150, 250])
            cert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(cert_table)
            story.append(Spacer(1, 20))
        
        # Vulnérabilités détectées
        if sslyze_analysis['vulnerabilities']:
            story.append(Paragraph("🚨 Vulnérabilités SSL/TLS détectées :", self.get_colored_style('#dc3545', bold=True)))
            story.append(Spacer(1, 10))
            
            vuln_data = [['Vulnérabilité', 'Gravité', 'Description']]
            for vuln in sslyze_analysis['vulnerabilities']:
                vuln_data.append([vuln['name'], vuln['severity'], vuln['description']])
            
            vuln_table = Table(vuln_data, colWidths=[120, 80, 200])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(vuln_table)
            story.append(Spacer(1, 20))
        
        # Log technique
        story.append(Paragraph("🔍 Extrait du rapport technique :", self.get_colored_style('#6c757d', bold=True)))
        story.append(Spacer(1, 10))
        
        # Nettoyer et formater les résultats
        cleaned_results = self._clean_sslyze_output(results)
        story.append(Paragraph(f"<font name='Courier' size='7'>{cleaned_results}</font>", self.styles['normal']))
        story.append(Spacer(1, 20))
        
        # Recommandations
        recommendations = self._get_sslyze_recommendations(sslyze_analysis)
        story.append(Paragraph("🛡️ Recommandations de sécurité SSL/TLS :", self.get_colored_style('#dc3545', bold=True)))
        story.append(Spacer(1, 10))
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['normal']))
            story.append(Spacer(1, 5))
        
        doc.build(story)
        return filename

    def _analyze_sslyze_results(self, results):
        """Analyse les résultats SSLyze"""
        import re
        
        analysis = {
            'ssl_configured': False,
            'cert_valid': False,
            'critical_issues': 0,
            'warnings': 0,
            'protocols': {},
            'certificate_info': {},
            'vulnerabilities': []
        }
        
        try:
            lines = results.split('\n')
            
            for line in lines:
                # Détecter si SSL est configuré
                if 'SSL' in line or 'TLS' in line:
                    analysis['ssl_configured'] = True
                
                # Détecter protocoles supportés
                if re.search(r'(SSL|TLS)v?\d+\.\d+', line):
                    protocol_match = re.search(r'(SSL|TLS)v?(\d+\.\d+)', line)
                    if protocol_match:
                        protocol = protocol_match.group(0)
                        if 'Supported' in line or 'ACCEPTED' in line:
                            analysis['protocols'][protocol] = 'Supporté'
                        elif 'Not Supported' in line or 'REJECTED' in line:
                            analysis['protocols'][protocol] = 'Non supporté'
                
                # Détecter certificat valide
                if 'Certificate' in line and 'Valid' in line:
                    analysis['cert_valid'] = True
                
                # Détecter problèmes critiques
                if any(issue in line.lower() for issue in ['vulnerable', 'insecure', 'weak', 'deprecated']):
                    analysis['critical_issues'] += 1
                
                # Détecter avertissements
                if any(warning in line.lower() for warning in ['warning', 'caution', 'notice']):
                    analysis['warnings'] += 1
                
                # Extraire infos certificat
                if 'Subject:' in line:
                    analysis['certificate_info']['Sujet'] = line.split('Subject:')[1].strip()
                elif 'Issuer:' in line:
                    analysis['certificate_info']['Émetteur'] = line.split('Issuer:')[1].strip()
                elif 'Serial Number:' in line:
                    analysis['certificate_info']['Numéro de série'] = line.split('Serial Number:')[1].strip()
                
            # Analyser vulnérabilités connues
            if 'ROBOT' in results:
                analysis['vulnerabilities'].append({
                    'name': 'ROBOT Attack',
                    'severity': 'ÉLEVÉ',
                    'description': 'Vulnérabilité dans l\'implémentation RSA'
                })
            
            if 'Heartbleed' in results:
                analysis['vulnerabilities'].append({
                    'name': 'Heartbleed',
                    'severity': 'CRITIQUE',
                    'description': 'Fuite de mémoire OpenSSL'
                })
                
        except Exception as e:
            print(f"[DEBUG] Erreur analyse SSLyze: {e}")
        
        return analysis

    def _get_ssl_security_level(self, protocol):
        """Retourne le niveau de sécurité du protocole SSL/TLS"""
        if 'SSL' in protocol or 'TLS1.0' in protocol or 'TLS1.1' in protocol:
            return 'OBSOLÈTE - DANGEREUX'
        elif 'TLS1.2' in protocol:
            return 'ACCEPTABLE'
        elif 'TLS1.3' in protocol:
            return 'RECOMMANDÉ'
        return 'INCONNU'

    def _clean_sslyze_output(self, results):
        """Nettoie la sortie SSLyze pour le PDF"""
        import re
        
        # Prendre les parties importantes
        lines = results.split('\n')
        important_lines = []
        
        for line in lines[:40]:
            if any(keyword in line.lower() for keyword in 
                   ['ssl', 'tls', 'certificate', 'cipher', 'protocol', 'vulnerability']):
                important_lines.append(line.strip())
        
        if len(important_lines) < 20:
            important_lines = lines[:30]
        
        cleaned = '\n'.join(important_lines)
        cleaned = re.sub(r'[^\x20-\x7E\n]', '', cleaned)
        cleaned = cleaned.replace('\n', '<br/>')
        
        if len(cleaned) > 2000:
            cleaned = cleaned[:2000] + '<br/>[... Log tronqué pour le PDF ...]'
        
        return cleaned

    def _get_sslyze_recommendations(self, analysis):
        """Recommandations selon les résultats SSLyze"""
        recommendations = []
        
        if analysis['critical_issues'] > 0:
            recommendations.extend([
                "🚨 URGENT : Corrigez les vulnérabilités SSL/TLS critiques détectées",
                "Mettez à jour immédiatement votre configuration SSL/TLS",
                "Désactivez les protocoles et chiffrements obsolètes"
            ])
        
        if not analysis['ssl_configured']:
            recommendations.append("🔒 CRITIQUE : Configurez SSL/TLS sur votre serveur")
        
        if not analysis['cert_valid']:
            recommendations.append("📜 Installez un certificat SSL/TLS valide et vérifié")
        
        # Recommandations par protocole
        protocols = analysis.get('protocols', {})
        for protocol, status in protocols.items():
            if status == 'Supporté' and ('SSL' in protocol or 'TLS1.0' in protocol or 'TLS1.1' in protocol):
                recommendations.append(f"⚠️ Désactivez le protocole obsolète {protocol}")
        
        if 'TLS1.3' not in [p for p in protocols.keys() if protocols[p] == 'Supporté']:
            recommendations.append("🔐 Activez TLS 1.3 pour une sécurité optimale")
        
        recommendations.extend([
            "🛡️ Configurez des suites de chiffrement sécurisées uniquement",
            "📊 Effectuez des tests SSL/TLS réguliers avec SSLyze",
            "🔄 Mettez à jour régulièrement vos certificats SSL/TLS",
            "👥 Formez les équipes aux bonnes pratiques SSL/TLS",
            "📋 Implémentez HSTS (HTTP Strict Transport Security)",
            "🔍 Surveillez l'expiration des certificats",
            "⚡ Utilisez des certificats avec des algorithmes SHA-256 ou supérieurs"
        ])
        
        return recommendations

    def generate_generic_report(self, tool_name, results, target=None, summary_data=None):
        """Rapport générique pour tous les autres outils"""
        # Gérer spécialement Nikto
        if tool_name == "Nikto" and isinstance(results, str):
            return self.generate_nikto_report(results, target)
        
        # Gérer spécialement Acunetix
        if tool_name == "Acunetix" and isinstance(results, str):
            try:
                import json
                acunetix_data = json.loads(results)
                return self.generate_acunetix_report(acunetix_data, target)
            except:
                pass  # Continuer avec le rapport générique si JSON échoue
        
        tool_clean = tool_name.lower().replace(' ', '_').replace('/', '_')
        filename = f"{tool_clean}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        story = []
        
        self._create_header_old(story, tool_name, target)
        
        # Résumé si fourni
        if summary_data:
            story.append(Paragraph("📊 Résumé", self.styles['SDVHeader']))
            summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#007bff')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 20))
        
        # Résultats
        story.append(Paragraph(f"📋 Résultats de {tool_name}", self.styles['SDVHeader']))
        
        # Nettoyer et limiter les résultats
        if isinstance(results, str):
            results_clean = results.replace('\n', '<br/>')
            if len(results_clean) > 4000:
                results_clean = results_clean[:4000] + '<br/><br/>[... Résultats tronqués ...]'
            story.append(Paragraph(results_clean, self.styles['CodeBlock']))
        else:
            story.append(Paragraph(str(results), self.styles['CodeBlock']))
        
        doc.build(story)
        return filename
