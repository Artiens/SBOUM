🛡️ SBOM-CVE-Enricher

📝 Description du Projet

SBOM-CVE-Enricher est un pipeline d'analyse de sécurité conçu pour traiter des listes de dépendances (issues de SBOM ou de documents PDF) et les enrichir avec des données de vulnérabilités (CVEs) provenant de la base de données OSV (Open Source Vulnerability).

Ce projet se distingue par sa capacité à gérer l'ambiguïté des écosystèmes (PyPI, npm, Go, etc.) en appliquant une logique de dominance (filtre de Pareto à 70%) ou en offrant un mode de sélection manuel à l'utilisateur, tout en permettant des analyses incrémentales et limitées.

✨ Fonctionnalités Clés

    Source Flexible : Extrait les dépendances à partir de fichiers SBOM (JSON) ou de PDF.

    Scan OSV Incrémental : Interroge l'API OSV pour récupérer les vulnérabilités. Les résultats sont enregistrés de manière incrémentale (osv_results_partial.json), permettant d'arrêter et de reprendre le scan à tout moment.

    Filtre d'Écosystème Intelligent (Pareto) :

        Identifie l'écosystème le plus probable (par exemple, si 90% des paquets uniques sont PyPI).

        Si un écosystème est dominant à plus de 70%, le scan est automatiquement filtré pour ne garder que les CVEs de cet écosystème.

        Si la dominance est inférieure à 70%, tous les résultats sont conservés.

    Mode de Sélection Manuel (--manual-select) :

        Désactive le filtre de Pareto.

        Pour les paquets dont l'écosystème est ambigu (vulnérabilités associées à plusieurs écosystèmes), affiche la distribution des pourcentages et permet à l'utilisateur de choisir manuellement l'écosystème correct pour ce paquet.

    Limitation du Scan (--limit N) : Permet de limiter le scan aux N premières librairies du SBOM, idéal pour les tests ou les longs SBOMs.

🚀 Installation

Prérequis

    Python 3.8+

    Dépendances Python spécifiques (non listées dans les fichiers fournis, mais nécessaires à sbom_to_csv.py).

Clônage du Dépôt

Bash

git clone https://github.com/votre_utilisateur/votre_repo.git
cd votre_repo

Configuration des Entrées

Par défaut, le pipeline s'attend à trouver le fichier de dépendances source :

    oss-listings.pdf : Le PDF ou SBOM source.

🛠️ Utilisation du Pipeline

Le script principal est main_from_csv.py. Il orchestre l'extraction, le scan et le filtrage.

Mode de Base (Filtre Pareto 70%)

Le script analyse le SBOM, effectue le scan OSV et applique la règle de dominance si elle s'applique.
Bash

python main_from_csv.py

    Sortie : Le rapport final de vulnérabilités enrichies est généré dans osv_results_pareto.json.

Option 1 : Limiter le Scan

Pour ne tester que les 40 premières librairies :
Bash

python main_from_csv.py --limit 40

Option 2 : Sélection Manuelle de l'Écosystème

Pour désactiver la règle de Pareto et choisir manuellement l'écosystème pour les paquets ambigus :
Bash

python main_from_csv.py --manual-select

Le processus s'interrompra pour chaque paquet ambigu en affichant les options et les pourcentages de chance (basés sur les CVEs trouvées) :

================================================================================
Conflicting ecosystems for package: 'my-ambiguous-lib'
Potential ecosystems (based on linked CVEs):
  [1] PyPI (50.00% chance)
  [2] Maven (50.00% chance)
  [u] Leave as unknown (keep all CVEs for this package)
Select dominant ecosystem [1-2] or [u]: 

Option 3 : Combiner Limite et Manuel

Bash

python main_from_csv.py --limit 40 --manual-select

📁 Fichiers de Sortie

Fichier de Sortie	Généré par	Description	Incrémental
dependencies.csv	sbom_to_csv.py	Liste brute des dépendances (nom, version, écosystème, fournisseur).	Non
final_sbom_data.csv	main_from_csv.py (Étape 2)	Liste nettoyée et potentiellement limitée des paquets à scanner.	Non
osv_results_partial.json	osv_scanner.py (Étape 3)	Résultats du scan OSV, mis à jour après chaque paquet scanné. Permet l'arrêt et la reprise du code.	Oui
osv_results.json	osv_scanner.py (Étape 3)	Résultats du scan OSV complet, après achèvement.	Non
osv_results_pareto.json	detect_eco.py (Étape 4)	Rapport final après l'application du filtre de Pareto ou du choix manuel.	Non
