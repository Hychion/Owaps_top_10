# OWASP Tester

Outil de test de sécurité automatisé aligné sur le **OWASP Top 10 (2021)**, écrit en **Rust**.  
Conçu exclusivement pour des tests autorisés : pentests, CTF, audits de sécurité.

---

## Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Mise en route rapide](#mise-en-route-rapide)
- [Modules disponibles](#modules-disponibles)
- [Commandes CLI](#commandes-cli)
- [Environnement de lab Docker](#environnement-de-lab-docker)
- [Tests](#tests)
- [Structure du projet](#structure-du-projet)
- [Ajouter un nouveau module](#ajouter-un-nouveau-module)
- [Éthique et périmètre](#éthique-et-périmètre)

---

## Vue d'ensemble

```
owasp-tester scan --target http://localhost:8083 --modules "A03:2021" --format terminal
```

```
OWASP Tester  3 findings on http://localhost:8083

╭────────────┬──────────┬───────────────────────────────┬────────────────────────────╮
│ Top 10 ID  │ Severity │ Title                         │ URL                        │
├────────────┼──────────┼───────────────────────────────┼────────────────────────────┤
│ A03:2021   │ Critical │ Injection vulnerability       │ http://localhost:8083       │
╰────────────┴──────────┴───────────────────────────────┴────────────────────────────╯
```

Chaque module :
- implémente un test du Top 10 OWASP via requêtes HTTP
- retourne un `Finding` structuré (ID, sévérité, evidence, remédiation)
- est testé en isolation avec `wiremock` (aucun réseau requis pour les tests unitaires)
- est validé en intégration contre un lab Docker custom dédié

---

## Prérequis

| Outil | Version minimale | Rôle |
|-------|-----------------|------|
| [Rust](https://rustup.rs) | 1.75+ | Compilation |
| [Docker](https://docs.docker.com/get-docker/) | 24+ | Labs de test |
| docker compose | v2 | Orchestration des labs |
| `cargo-llvm-cov` *(optionnel)* | — | Couverture de code |

Vérification rapide :
```bash
rustc --version
docker --version
docker compose version
```

---

## Installation

```bash
# Cloner le dépôt
git clone <url-du-repo>
cd Owasp_tester

# Compiler en mode debug
cargo build

# Compiler en mode release (optimisé, binaire final)
cargo build --release
```

Le binaire est disponible dans `./target/debug/owasp-tester` ou `./target/release/owasp-tester`.

---

## Mise en route rapide

### 1. Démarrer les labs Docker

```bash
# Bootstrap complet : build des images + démarrage des containers
./scripts/setup-lab.sh

# Ou via Make
make lab-up
```

### 2. Vérifier que les labs sont prêts

```bash
make lab-status
```

```
NAMES               STATUS                   PORTS
owasp-lab-a01       Up (healthy)             0.0.0.0:8081->5000/tcp
owasp-lab-a02       Up (healthy)             0.0.0.0:8082->5001/tcp
owasp-lab-a03       Up (healthy)             0.0.0.0:8083->5002/tcp
owasp-lab-a05       Up (healthy)             0.0.0.0:8085->5003/tcp
owasp-lab-a07       Up (healthy)             0.0.0.0:8087->5004/tcp
owasp-lab-a10       Up (healthy)             0.0.0.0:8090->5005/tcp
```

### 3. Lancer un scan

```bash
# Scan d'un seul module
make scan-a03

# Scan de tous les modules contre tous les labs
make scan-all

# Scan manuel avec options
./target/debug/owasp-tester scan \
  --target http://localhost:8083 \
  --modules "A03:2021" \
  --format json \
  --output reports/result.json
```

### 4. Arrêter les labs

```bash
make lab-down
```

---

## Modules disponibles

```bash
./target/debug/owasp-tester list
```

| Top 10 ID | Nom | Ce qui est testé |
|-----------|-----|-----------------|
| **A01:2021** | Broken Access Control | Forced browsing `/admin`, IDOR (énumération d'IDs), override de méthodes HTTP |
| **A02:2021** | Cryptographic Failures | HTTP sans TLS, HSTS absent ou trop court, cookies sans `Secure`, données sensibles en URL |
| **A03:2021** | Injection | SQL injection (error-based), XSS réfléchi, SSTI (`{{7*7}}` → 49) |
| **A05:2021** | Security Misconfiguration | Headers manquants (CSP, X-Frame-Options…), erreurs verbeuses, endpoints debug exposés (`/actuator`, `/phpinfo`) |
| **A07:2021** | Authentication Failures | Credentials par défaut, pas de rate limiting, erreurs d'auth différenciées (user enumeration), cookies de session non sécurisés |
| **A10:2021** | SSRF | Injection d'URL interne/loopback/IMDS dans 20 paramètres courants (`url`, `redirect`, `src`, `fetch`…) |

> **A04, A06, A08, A09** ne sont pas implémentés : ils ne sont pas détectables de manière fiable par scan HTTP externe (design, composants, intégrité, logging).

---

## Commandes CLI

### `scan` — Lancer un scan

```bash
owasp-tester scan [OPTIONS] --target <URL>
```

| Option | Description | Exemple |
|--------|-------------|---------|
| `--target <URL>` | URL cible **(obligatoire)** | `http://localhost:8083` |
| `--all` | Exécuter tous les modules | |
| `--modules <IDs>` | IDs séparés par virgule | `"A01:2021,A03:2021"` |
| `--format <FORMAT>` | `terminal` *(défaut)*, `json`, `html` | `--format json` |
| `--output <FILE>` | Fichier de sortie (json/html) | `--output reports/result.json` |
| `--auth-token <TOKEN>` | Bearer token pour scans authentifiés | |
| `--insecure` | Désactiver la vérification TLS (labs internes) | |
| `-v / -vv / -vvv` | Verbosité croissante (info / debug / trace) | |

**Exemples :**

```bash
# Tous les modules, sortie terminal
owasp-tester scan --target http://localhost:8081 --all

# Module spécifique, rapport JSON
owasp-tester scan --target http://localhost:8083 --modules "A03:2021" \
  --format json --output reports/a03.json

# Scan authentifié
owasp-tester scan --target http://app.internal --all \
  --auth-token "Bearer eyJ..." --insecure

# Mode verbose pour le débogage
owasp-tester scan --target http://localhost:8085 --modules "A05:2021" -vv
```

### `list` — Lister les modules

```bash
owasp-tester list
```

---

## Environnement de lab Docker

Chaque lab est une application volontairement vulnérable, isolée dans un container Docker.

| Lab | Port local | Vulnérabilité simulée |
|-----|-----------|----------------------|
| `lab-a01` | `8081` | IDOR sur `/api/users/<id>`, panel admin sans auth |
| `lab-a02` | `8082` | HTTP sans HTTPS, cookies sans `Secure`/`HttpOnly`/`SameSite`, HSTS absent |
| `lab-a03` | `8083` | SQL injection (SQLite), XSS réfléchi (`/search?q=`), SSTI Jinja2 (`/greet?name=`) |
| `lab-a05` | `8085` | Zéro header de sécurité, `/actuator/env` exposé avec secrets, erreurs verbeuses |
| `lab-a07` | `8087` | Credentials par défaut (`admin:admin`), pas de rate limiting, erreurs différenciées |
| `lab-a10` | `8090` | Endpoint `/fetch?url=` qui retourne le contenu de n'importe quelle URL |

### Commandes Docker utiles

```bash
make lab-build        # Construire toutes les images
make lab-up           # Démarrer tous les containers
make lab-down         # Arrêter et supprimer les containers
make lab-status       # Voir l'état de santé de chaque container
make lab-logs         # Suivre les logs en temps réel
make clean-docker     # Supprimer images et containers
```

### Script de bootstrap

```bash
# Première installation complète
./scripts/setup-lab.sh

# Options disponibles
./scripts/setup-lab.sh --clean      # Nettoyage avant build
./scripts/setup-lab.sh --test-only  # Build des images sans démarrer les labs
```

---

## Tests

### Tests unitaires (rapides, aucun Docker requis)

Les tests unitaires utilisent `wiremock` pour simuler les réponses HTTP.  
Ils vérifient chaque module isolément : détection d'une vulnérabilité ET cas propre.

```bash
# Lancer tous les tests unitaires
make test

# Avec output détaillé
cargo test --lib -- --nocapture

# Un seul module
cargo test --lib a03_injection

# Avec filtre par nom de test
cargo test --lib detects_sqli
```

**Couverture attendue :** chaque module a au minimum :
- un test qui **détecte** la vulnérabilité (mock vulnérable)
- un test qui **ne produit aucun finding** (mock propre)

### Tests d'intégration (Docker requis)

Les tests d'intégration spawnent les containers Docker automatiquement via `testcontainers-rs`,  
attendent le health check, exécutent le module, puis détruisent le container.

```bash
# Prérequis : images buildées
make lab-build

# Lancer les tests d'intégration
make test-integration

# Ou directement
cargo test --features integration-tests -- --test-threads=1 --nocapture
```

> `--test-threads=1` est important pour éviter les conflits de ports entre containers.

### Couverture de code

```bash
# Installer cargo-llvm-cov (une seule fois)
cargo install cargo-llvm-cov

# Rapport HTML interactif
make coverage
# → ouvre coverage/index.html

# Format lcov (CI)
make coverage-ci
# → génère lcov.info
```

Seuil minimum configuré : **80%** de couverture de ligne.

### Récapitulatif des commandes de test

```bash
make test                  # Tests unitaires (défaut)
make test-unit             # Explicitement les tests unitaires
make test-integration      # Tests d'intégration (Docker)
make coverage              # Couverture HTML
make coverage-ci           # Couverture lcov (CI)
make lint                  # cargo clippy -D warnings
make fmt                   # cargo fmt
make fmt-check             # Vérification format (CI)
```

---

## Structure du projet

```
owasp_tester/
├── src/
│   ├── main.rs                          # Entry point, init tracing
│   ├── cli/
│   │   ├── args.rs                      # Arguments clap (Scan, List)
│   │   └── mod.rs                       # Logique run_scan(), run_list()
│   ├── core/
│   │   ├── error.rs                     # ScanError (thiserror)
│   │   ├── models.rs                    # Target, Finding, Severity, Report
│   │   ├── session.rs                   # Client HTTP (reqwest + cookies)
│   │   ├── scanner.rs                   # Orchestrateur async (tokio JoinSet)
│   │   └── reporter.rs                  # Terminal / JSON / HTML
│   └── modules/
│       ├── base.rs                      # Trait OwaspModule + Top10Id enum
│       ├── mod.rs                       # Registre all_modules(), modules_by_id()
│       ├── a01_broken_access_control.rs
│       ├── a02_cryptographic_failures.rs
│       ├── a03_injection.rs
│       ├── a05_security_misconfiguration.rs
│       ├── a07_auth_failures.rs
│       └── a10_ssrf.rs
├── docker/
│   ├── lab-a01/   # Flask — IDOR + admin path
│   ├── lab-a02/   # Flask — HTTP + cookies insecures
│   ├── lab-a03/   # Flask + SQLite — SQLi + XSS + SSTI
│   ├── lab-a05/   # Flask — headers manquants + debug endpoints
│   ├── lab-a07/   # Flask — credentials par défaut + no rate limit
│   └── lab-a10/   # Flask — SSRF via paramètre url/uri/href
├── tests/
│   └── integration/
│       ├── containers.rs                # Définitions testcontainers-rs
│       └── mod.rs                       # Tests d'intégration par module
├── payloads/
│   ├── xss_basic.txt
│   └── sqli_basic.txt
├── .claude/
│   ├── settings.json                    # Permissions + hooks Claude Code
│   └── commands/
│       ├── new-module.md                # /new-module A06:2021
│       ├── scan.md                      # /scan
│       └── rapport.md                   # /rapport
├── Cargo.toml
├── docker-compose.yml
├── Makefile
├── config.yaml
├── rustfmt.toml
└── CLAUDE.md
```

---

## Ajouter un nouveau module

Utilise la commande Claude Code intégrée :

```
/new-module A06:2021
```

Ou manuellement :

**1. Créer `src/modules/a06_vulnerable_components.rs`** en implémentant le trait :

```rust
use async_trait::async_trait;
use crate::modules::base::{OwaspModule, Top10Id};
use crate::core::{error::ScanError, models::{Finding, Target}, session::Session};

pub struct A06VulnerableComponents;

#[async_trait]
impl OwaspModule for A06VulnerableComponents {
    fn top10_id(&self) -> Top10Id { Top10Id::A06 }
    fn name(&self) -> &'static str { "Vulnerable and Outdated Components" }
    fn description(&self) -> &'static str { "..." }

    async fn run(&self, target: &Target, session: &Session) -> Result<Option<Finding>, ScanError> {
        // logique ici
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    // tests wiremock ici
}
```

**2. Enregistrer dans `src/modules/mod.rs`** :

```rust
pub mod a06_vulnerable_components;

// dans all_modules() :
Arc::new(A06VulnerableComponents),
```

**3. Créer le lab Docker** dans `docker/lab-a06/` avec son `Dockerfile` et `app.py`.

**4. Vérifier** :

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test --lib a06
```

---

## Éthique et périmètre

> **Ce projet est destiné exclusivement à des tests de sécurité autorisés.**

- Ne jamais utiliser cet outil contre des systèmes que vous ne possédez pas  
  ou pour lesquels vous n'avez pas d'autorisation écrite explicite.
- Les labs Docker fournis sont des environnements **volontairement vulnérables**  
  à utiliser uniquement en local ou dans un réseau isolé.
- Les payloads inclus sont des sondes de détection bénignes,  
  pas des exploits d'extraction de données.

Contextes d'utilisation légitimes : pentests avec contrat, CTF, audits de sécurité, recherche défensive.
