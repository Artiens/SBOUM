# 🛡️ SBOM-CVE-Enricher

## 📝 Description du Projet

**SBOM-CVE-Enricher** est un pipeline d'analyse de sécurité conçu pour traiter des listes de dépendances (issues de SBOM ou de documents PDF) et les enrichir avec des données de vulnérabilités (CVEs) provenant de la base de données **OSV (Open Source Vulnerability)**.

Ce projet se distingue par sa capacité à gérer l'ambiguïté des écosystèmes (PyPI, npm, Go, etc.) en appliquant une logique de dominance (**filtre de Pareto à 70%**) ou en offrant un **mode de sélection manuel**, tout en permettant des analyses incrémentales et limitées.

---

## ✨ Fonctionnalités Clés

* **Source Flexible** : Extrait les dépendances à partir de fichiers **SBOM** (JSON) ou de **PDF**.
* **Scan OSV Incrémental** : Les résultats sont enregistrés de manière incrémentale (`osv_results_partial.json`), permettant d'**arrêter et de reprendre le scan** à tout moment si le SBOM est trop long.
* **Filtre d'Écosystème Intelligent (Pareto à 70%)** : Applique un filtrage automatique sur les CVEs si un écosystème est clairement dominant.
* **Mode de Sélection Manuel** (`--manual-select`) :
    * Désactive le filtre de Pareto.
    * Pour les paquets ambigus, affiche la **distribution des pourcentages** des écosystèmes possibles et demande à l'utilisateur de **choisir**.
* **Limitation du Scan** (`--limit N`) : Permet de **limiter le scan** aux $N$ premières librairies du SBOM.

---

## 🚀 Installation

### Prérequis

* Python 3.8+
* Dépendances Python nécessaires aux scripts (ex: `pdfminer.six` pour les PDF, `requests`, etc.).

### Fichiers d'Entrée

Le pipeline s'attend à trouver le fichier de dépendances source dans le répertoire racine :
* **`oss-listings.pdf`** : Le PDF ou SBOM source.

---

## 🛠️ Utilisation du Pipeline

Le script principal est `main_from_csv.py`.

### 1. Mode de Base (Filtre Pareto 70%)

Le scan complet est exécuté avec l'application automatique du filtre de Pareto.

```bash
python main_from_csv.py
