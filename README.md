# EASM Platform

[![CI](https://github.com/elysec/easm-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/elysec/easm-platform/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)

**External Attack Surface Management** — plateforme open-source de découverte et de surveillance continue des surfaces d'attaque exposées sur Internet.

## Pourquoi ?

Les organisations déploient en permanence de nouveaux services, domaines et adresses IP sans toujours en garder la trace. Chaque actif oublié — un serveur mal configuré, un port ouvert, un sous-domaine non surveillé — est une porte d'entrée potentielle. L'EASM Platform automatise cette veille : elle cartographie l'empreinte Internet d'une organisation, la réanalyse régulièrement et détecte les changements suspects avant qu'ils ne deviennent des incidents.

## Comment ?

La plateforme fonctionne par **vagues de découverte itératives** : à partir d'un domaine racine, elle énumère les sous-domaines, résout les adresses IP, sonde les services exposés et rebondit sur chaque nouvelle cible découverte — le tout orchestré automatiquement jusqu'à épuisement de la surface visible.

### Outils intégrés

| Outil | Rôle |
|---|---|
| WHOIS | Résolution DNS, informations de registre |
| Shodan | Empreinte des services exposés, ports ouverts, CVEs |
| Censys | Inventaire des hôtes et services |
| Subfinder / Amass / MerkleMap | Énumération passive de sous-domaines |
| theHarvester | OSINT multi-source |
| HTTPX | Sonde HTTP et empreinte technologique |
| Reverse DNS | Résolution inverse IP → domaine |
| Email Security | Vérification SPF / DKIM / DMARC |
| Nmap | Scan de ports (passif) |
| Holehe | Vérification de présence email |

Chaque outil est conteneurisé et exécuté via Celery, avec un contrat `scan.py` / `parse.py` standard qui permet d'en ajouter de nouveaux sans modifier le noyau.

### Stack technique

| Couche | Technologie |
|---|---|
| Frontend | Next.js (App Router) + TypeScript |
| API | FastAPI (Python 3.12) |
| File d'attente | Celery + Redis |
| Base de données | PostgreSQL (JSONB) |
| Infrastructure | Docker Compose |

### Démarrage rapide

```bash
# Lancer tous les services
docker compose up -d

# Lancer le frontend en développement
cd frontend && npm run dev
```

La documentation complète est dans [`CLAUDE.md`](CLAUDE.md).

## Développement

```bash
# Backend — tests + lint
cd backend && source ../.venv/bin/activate
pytest --cov=backend --cov-report=term   # couverture du backend
ruff check . && black --check --diff .   # lint + format

# Frontend
cd frontend && npm run dev
```

La couverture est mesurée dans la CI à chaque PR — le statut du workflow
[CI](https://github.com/elysec/easm-platform/actions/workflows/ci.yml)
donne l'état de la branche `main`.
