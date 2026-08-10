# Présentation des outils EASM

Chaque outil suit le même contrat : un fichier `scan.py` (exécution — appels API ou sous-processus) et un fichier `parse.py` (transformation du résultat brut en findings structurés). Tous les outils sont exécutés via Celery, avec création synchrone du `ScanJob` pour éviter les courses de polling.

---

## WHOIS

**Comment ça fonctionne :** Interroge les registres WHOIS via la bibliothèque `python-whois`. Le domaine est d'abord réduit à son domaine enregistrable (ex: `sous.domaine.example.com` → `example.com`). Les dates (création, expiration, mise à jour) sont normalisées en ISO 8601.

**Type d'actif cible :** `domain`, `subdomain`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `domain_registration` | `info` | Bureau d'enregistrement, dates de création/expiration/mise à jour, serveurs DNS, statuts, emails, DNSSEC, organisation, pays |
| `domain_expiry` | `medium` ou `high` | Émis uniquement si le domaine expire dans ≤ 30 jours (`medium`) ou est déjà expiré (`high`) |

**Chaînage :** Résout le domaine en IP via DNS (A-record) → déclenche un scan **Shodan** sur l'IP.

---

## Shodan

**Comment ça fonctionne :** Interroge l'API Shodan Host (`/shodan/host/{ip}`) avec la clé `SHODAN_API_KEY`. Récupère les informations de l'hôte, les services exposés et les vulnérabilités CVE associées.

**Type d'actif cible :** `ip`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `host_info` | `info` | IP, organisation, FAI, ASN, noms d'hôte, domaines, pays, ville, coordonnées, OS, tags, ports exposés |
| `open_port` | `info` | Port, protocole (tcp/udp), produit, version, bannière (500 premiers caractères) |
| `vulnerability` | `info` à `critical` | CVE ID, score CVSS, résumé. Sévérité calculée depuis le CVSS (≥9.0 critical, ≥7.0 high, ≥4.0 medium, ≥0.1 low) |

**Chaînage :** Cherche un domaine via Reverse DNS (cache ou PTR) → déclenche un scan **WHOIS** sur le domaine trouvé.

---

## Censys

**Comment ça fonctionne :** Interroge l'API Censys Host v2 (`/v2/hosts/{ip}`) avec les identifiants `CENSYS_API_ID` et `CENSYS_API_SECRET`. Récupère les informations de localisation, ASN, OS et services exposés.

**Type d'actif cible :** `ip`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `host_info` | `info` | IP, organisation, ASN, pays, ville, coordonnées, OS, ports exposés |
| `open_port` | `info` | Port, protocole (tcp/udp), nom du service, logiciels détectés, bannière |

**Chaînage :** Même logique que Shodan → Reverse DNS → **WHOIS**.

---

## Reverse DNS

**Comment ça fonctionne :** Utilise `socket.gethostbyaddr()` (résolution PTR native) pour obtenir les noms d'hôte associés à une IP. Simple, sans dépendance externe.

**Type d'actif cible :** `ip`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `reverse_dns` | `info` | IP, liste des noms d'hôte résolus |

**Chaînage :** Extrait le domaine enregistrable du premier hostname → déclenche un scan **WHOIS**.

---

## Email Security

**Comment ça fonctionne :** Vérifie les enregistrements SPF, DMARC et DKIM d'un domaine via des requêtes DNS (`dig` TXT). Pour DKIM, sonde une liste de sélecteurs courants (`default`, `google`, `selector1`, `selector2`, `k1`, `mail`, `dkim`). L'absence de SPF ou DMARC est elle-même un finding (faille de sécurité) — contrairement à DKIM où l'absence de réponse n'est pas une preuve d'absence.

**Type d'actif cible :** `domain`, `subdomain`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `email_security` — SPF absent | `medium` | `check: "spf"`, `present: false` |
| `email_security` — SPF présent | `info` | `check: "spf"`, `present: true`, enregistrement complet |
| `email_security` — DMARC absent | `high` | `check: "dmarc"`, `present: false` — risque d'usurpation |
| `email_security` — DMARC présent | `info` à `medium` | Politique extraite (`reject`=info, `quarantine`=low, `none`=medium) |
| `email_security` — DKIM trouvé | `info` | `check: "dkim"`, sélecteurs trouvés |

---

## theHarvester

**Comment ça fonctionne :** Combine deux approches : (1) l'API publique crt.sh pour les certificats Transparency (source fiable, pas d'auth, 1-5s), et (2) le CLI theHarvester en sous-processus avec 7 sources sans clé API (crtsh, duckduckgo, bing, otx, threatminer, hackertarget, rapiddns). Timeout de 90s pour le sous-processus. Les résultats sont dédoublonnés et les IPs brutes extraites des entrées SAN des certificats.

**Type d'actif cible :** `domain`, `subdomain`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `discovered_assets` | `info` | `category: "hosts"`, liste des sous-domaines/IPs/emails/URLs découverts, sources utilisées |

**Flux humain :** Les sous-domaines découverts ne sont pas automatiquement ajoutés. Ils sont présentés dans l'interface (`SuggestHostsPanel`) pour validation manuelle avant création en tant qu'Assets.

---

## Subfinder

**Comment ça fonctionne :** Exécute le binaire `subfinder` en sous-processus avec l'option `-silent`. Le timeout est de 120s. En cas de timeout, les résultats partiels sont quand même retournés (meilleur effort). Filtre les wildcards et nettoie la sortie.

**Type d'actif cible :** `domain`, `subdomain`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `discovered_assets` | `info` | `category: "hosts"`, liste triée des sous-domaines découverts, sources utilisées |

Même schéma que theHarvester et Amass — compatible avec le flux de validation humaine `SuggestHostsPanel`.

---

## Amass

**Comment ça fonctionne :** Exécute le binaire `amass` en sous-processus avec le mode `enum` (passive). Timeout de 180s. Utilise `-passive` uniquement (pas de résolution DNS active). Comme Subfinder, les résultats partiels sont conservés en cas de timeout.

**Type d'actif cible :** `domain`, `subdomain`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `discovered_assets` | `info` | `category: "hosts"`, liste triée des sous-domaines découverts, sources utilisées |

---

## MerkleMap

**Comment ça fonctionne :** Interroge l'API REST de MerkleMap (`GET /v1/search?query=<domain>&type=wildcard`) qui indexe les certificats Transparency. Pagination automatique à travers tous les résultats. Nécessite `MERKLEMAP_API_KEY`. Filtre les résultats pour ne garder que les sous-domaines du domaine cible. Rejette les wildcards explicitement.

**Type d'actif cible :** `domain`, `subdomain`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `discovered_assets` | `info` | `category: "hosts"`, liste triée des sous-domaines découverts, `sources_used: ["merklemap"]` |

---

## HTTPX

**Comment ça fonctionne :** Exécute le binaire `httpx` de ProjectDiscovery en sous-processus, mode single-target (`-u <cible>`). Sonde à la fois HTTP et HTTPS. Options : `-tech-detect` (détection de technos), `-title`, `-status-code`, `-ip`, `-server`, `-cdn`, `-follow-redirects`, `-websocket`. Timeout de 90s (15s par cible via `-timeout`).

**Type d'actif cible :** `subdomain`, `ip`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `http_service` | `info` | URL, code HTTP, titre de la page, technologies détectées, serveur web, CDN, IP, redirection, type de contenu, longueur, websocket |

Les technologies détectées incluent les frameworks, librairies JS, serveurs, etc. (ex: React, Nginx, Cloudflare, WordPress).

---

## Nmap

**Comment ça fonctionne :** Exécute le binaire `nmap` en sous-processus avec les options `-sT` (TCP connect scan — pas besoin de raw sockets ni root), `-sV` (détection de version de service) et `--top-ports 100` (les 100 ports les plus courants). Sortie XML (`-oX -`). Timeout de 120s. Parse le XML pour extraire l'IP, les hostnames, l'OS et la liste des services.

**Type d'actif cible :** `ip`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `host_info` | `info` | IP, noms d'hôte, OS détecté, liste des ports ouverts |
| `open_port` | `info` | Port, protocole, produit, version, bannière |
| `vulnerability` | `info` à `critical` | CVE ID et score CVSS — corrélés depuis Shodan CVEDB quand produit + version sont détectés |

**Note :** La corrélation CVE est best-effort et silencieuse en cas d'échec — le finding `open_port` existe toujours, les CVEs sont un bonus.

---

## Holehe

**Comment ça fonctionne :** Exécute le CLI `holehe` en sous-processus. Comme holehe n'a pas de sortie JSON stdout, il utilise le flag `-C` qui écrit un CSV dans le répertoire courant. Le scan s'exécute dans un dossier temporaire isolé. Vérifie la présence de l'email sur 100+ services (Twitter, Instagram, Spotify, etc.). Timeout de 90s.

**Type d'actif cible :** `email`

**Résultat produit :**

| Finding type | Sévérité | Contenu |
|---|---|---|
| `email_presence` | `info` | Email vérifié, liste des services où l'email est enregistré (nom, domaine, rate limit), nombre total |

Un seul finding par email (pas un par service) pour éviter d'inonder les résultats.

---

## Résumé — Matrice outils × findings

| Outil | Cible | `host_info` | `open_port` | `vuln` | `discovered_assets` | `domain_reg` | `domain_expiry` | `email_security` | `reverse_dns` | `http_service` | `email_presence` |
|---|---|---|---|---|---|---|---|---|---|---|---|
| WHOIS | Domaine | | | | | ✅ | ✅ | | | | |
| Shodan | IP | ✅ | ✅ | ✅ | | | | | | | |
| Censys | IP | ✅ | ✅ | | | | | | | | |
| Reverse DNS | IP | | | | | | | | ✅ | | |
| Email Security | Domaine | | | | | | | ✅ | | | |
| theHarvester | Domaine | | | | ✅ | | | | | | |
| Subfinder | Domaine | | | | ✅ | | | | | | |
| Amass | Domaine | | | | ✅ | | | | | | |
| MerkleMap | Domaine | | | | ✅ | | | | | | |
| HTTPX | Sous-domaine/IP | | | | | | | | | ✅ | |
| Nmap | IP | ✅ | ✅ | ✅ | | | | | | | |
| Holehe | Email | | | | | | | | | | ✅ |

## Flux de découverte

```
Domaine racine
  ├─ WHOIS ──→ chaîne vers Shodan (si IP résolue)
  ├─ Email Security
  ├─ theHarvester ──→ sous-domaines → validation humaine → nouveaux Assets
  ├─ Subfinder     ──→ sous-domaines → validation humaine → nouveaux Assets
  ├─ Amass         ──→ sous-domaines → validation humaine → nouveaux Assets
  └─ MerkleMap     ──→ sous-domaines → validation humaine → nouveaux Assets

IP (découverte via WHOIS, validation humaine, ou ajout manuel)
  ├─ Shodan      ──→ chaîne vers WHOIS (si domaine PTR trouvé)
  ├─ Censys      ──→ chaîne vers WHOIS
  ├─ Reverse DNS ──→ chaîne vers WHOIS
  ├─ Nmap         ──→ ports + services + CVEs
  └─ HTTPX        ──→ services HTTP + technologies

Sous-domaine
  └─ HTTPX        ──→ services HTTP + technologies

Email
  └─ Holehe       ──→ présence sur les plateformes
```

Chaque nouvel Asset découvert (via chaînage ou validation humaine) est réinjecté dans la boucle de découverte, créant une exploration itérative par vagues jusqu'à épuisement de la surface visible.
