import json
import re
import math
import hashlib
import hmac as hmac_lib
from collections import defaultdict, Counter

# ============================================================
# PARTIE 2 — PARSERS PROTOCOLAIRES
# ============================================================

def parse_zigbee_line(line: str) -> dict | None:
    regex = r"topic 'zigbee2mqtt/([^']+)',\s*payload '({.*})'"
    match = re.search(regex, line)

    if match:
        device_name = match.group(1)
        
        # Exclusion des messages d'administration et de diagnostic du coordinateur
        if device_name.startswith("bridge"):
            return None
            
        raw_json_string = match.group(2)

        try:
            payload = json.loads(raw_json_string)
            return {
                "device": device_name,
                "payload": payload
            }
        except json.JSONDecodeError:
            return None
            
    return None


def parse_zwave_line(line: str) -> dict | None:
    """Voir énoncé Partie 2, Exercice 2.2."""

    if "Value updated" not in line:
        return None

    # Correction : ajout des deux-points après "Value updated"
    regex = r"\[Node (\d+)\] Value updated:\s+([^\s]+)\s+(.*?)\s+=>\s+(.*)"
    match = re.search(regex, line)

    if match:
        node_id = f"node_{match.group(1)}"
        metric = match.group(2)
        new_val_str = match.group(4)

        try:
            val = float(new_val_str)
        except ValueError:
            val = new_val_str

        return {
            "device": node_id,
            "metric": metric,
            "value": val
        }

    return None


def parse_ha_line(line: str) -> dict | None:
    """Voir énoncé Partie 2, Exercice 2.3."""

    try:
        data = json.loads(line.strip())
        entity_id = data.get("entity_id")
        state_str = data.get("state")
        unit = data.get("unit")

        # Gestion propre des états non numériques
        try:
            parsed_state = float(state_str)
        except (ValueError, TypeError):
            parsed_state = state_str

        return {
            "device": entity_id,
            "state": parsed_state,
            "unit": unit,
            "raw": data
        }

    except json.JSONDecodeError:
        return None


# ============================================================
# PARTIE 3 — NORMALISATION SÉMANTIQUE
# ============================================================

ZIGBEE_KNOWN_FIELDS = {
    "power": "power",
    "current": "current",
    "voltage": "voltage",
    "energy": "energy",
    "battery": "battery",
    "linkquality": "link_quality",
}

# Champs à considérer comme "safety_critical" : voir Exercice 3.4.
# Un événement marqué ainsi doit toujours passer, quel que soit le
# filtre deadband (Property 2 du papier de recherche associé).
SAFETY_CRITICAL_FIELDS = {"alarm", "tamper", "contact"}


def normalize_zigbee(parsed: dict) -> list[dict]:
    """Voir énoncé Partie 3, Exercices 3.1 à 3.4."""

    if not parsed:
        return []

    events = []
    device_id = parsed["device"]

    # Exercice 3.1 : Un message Zigbee contient plusieurs métriques, on renvoie une liste
    for key, value in parsed["payload"].items():

        # Exercice 3.3 : Événements safety-critical
        safety_critical = key in SAFETY_CRITICAL_FIELDS

        if key in ZIGBEE_KNOWN_FIELDS:
            metric_name = ZIGBEE_KNOWN_FIELDS[key]

            try:
                metric_value = float(value)
            except (ValueError, TypeError):
                metric_value = None

        else:
            # Exercice 3.2 : Principe de préservation (Property 1)
            metric_name = f"unknown_{key}"
            metric_value = None

        events.append({
            "device_id": device_id,
            "protocol": "zigbee",
            "metric_name": metric_name,
            "metric_value": metric_value,
            "safety_critical": safety_critical,
            "raw": parsed
        })

    return events


def normalize_zwave(parsed: dict) -> list[dict]:
    """Voir énoncé Partie 3, Exercice 3.5."""

    if not parsed:
        return []

    try:
        metric_value = float(parsed["value"])
    except (ValueError, TypeError):
        metric_value = None

    return [{
        "device_id": parsed["device"],
        "protocol": "zwave",
        "metric_name": parsed["metric"],
        "metric_value": metric_value,
        "safety_critical": parsed["metric"] in SAFETY_CRITICAL_FIELDS,
        "raw": parsed
    }]


def normalize_ha(parsed: dict) -> list[dict]:
    """Voir énoncé Partie 3, Exercice 3.5."""

    if not parsed:
        return []

    try:
        metric_value = float(parsed["state"])
    except (ValueError, TypeError):
        metric_value = None

    return [{
        "device_id": parsed["device"],
        "protocol": "ha",
        "metric_name": "state",
        "metric_value": metric_value,
        "safety_critical": False,
        "raw": parsed["raw"]
    }]


# ============================================================
# PARTIE 4 — PARSER STREAMING (fichiers volumineux)
# ============================================================

def naive_ha_load(path: str):
    """
    Tentative naïve : charger tout le fichier avec json.load().
    Utilisée en Partie 4 uniquement pour CONSTATER l'échec — ne modifiez
    pas cette fonction, elle est censée lever une exception sur un
    fichier HA réel (objets JSON concaténés, pas un tableau unique).
    """

    with open(path, encoding="utf-8") as f:
        return json.load(f)


def streaming_parse_ha(path: str):
    """
    Implémentation de l'Algorithme 1 (parseur par comptage d'accolades).
    Doit produire un générateur qui yield chaque objet JSON top-level
    complet, au fur et à mesure, sans jamais garder en mémoire plus
    que l'objet en cours de construction.

    Voir énoncé Partie 4, Exercice 4.2.
    """

    buf = ""
    depth = 0

    with open(path, encoding="utf-8") as f:

        # On lit caractère par caractère
        while True:
            char = f.read(1)

            if not char:
                break

            if char == '{':
                depth += 1

            if depth > 0:
                buf += char

            if char == '}':
                depth -= 1

                # L'objet JSON est complet
                if depth == 0 and buf.strip():
                    try:
                        yield json.loads(buf)
                    except json.JSONDecodeError:
                        pass

                    buf = ""


# ============================================================
# PARTIE 5 — FILTRE DEADBAND
# ============================================================

def deadband_filter(events: list[dict], delta: float) -> list[dict]:
    """Voir énoncé Partie 5, Exercice 5.1."""

    # TODO
    filtered_events = []

    # Dictionnaire pour mémoriser la dernière valeur transmise
    # Clé : (device_id, metric_name), Valeur : dernière valeur transmise
    last_values = {}

    for event in events:

        # Condition 1 : Les événements de sécurité passent toujours (Exercice 5.1)
        if event.get("safety_critical"):
            filtered_events.append(event)
            continue

        # Condition 2 : Les événements inconnus (sans valeur) passent toujours (Exercice 5.2)
        if event.get("metric_value") is None:
            filtered_events.append(event)
            continue

        # Condition 3 : Le filtre deadband classique
        key = (event["device_id"], event["metric_name"])
        current_value = event["metric_value"]

        # Si on n'a jamais vu cette métrique, on la laisse passer
        if key not in last_values:
            filtered_events.append(event)
            last_values[key] = current_value

        else:
            # Si on l'a déjà vue, on vérifie si la variation dépasse le delta
            if abs(current_value - last_values[key]) >= delta:
                filtered_events.append(event)
                last_values[key] = current_value

    return filtered_events


# ============================================================
# PARTIE 6 — RÈGLES DE DÉTECTION DE BASE
# ============================================================

def detect_power_surge(events: list[dict], threshold_w: float = 2000) -> list[dict]:
    """Voir énoncé Partie 6, Exercice 6.1."""
    alerts = []
    for event in events:
        if event.get("metric_name") == "power" and event.get("metric_value") is not None:
            if event["metric_value"] > threshold_w:
                alerts.append(event)
    return alerts



def detect_replay(events: list[dict], window: int = 3) -> list[dict]:
    """Voir énoncé Partie 6, Exercice 6.2."""
    from collections import defaultdict
    alerts = []
    history = defaultdict(list)
    
    for event in events:
        if event.get("metric_value") is None:
            continue
            
        key = (event["device_id"], event["metric_name"])
        history[key].append(event)
        
        if len(history[key]) > window:
            history[key].pop(0)
            
        if len(history[key]) == window:
            val_reference = history[key][0]["metric_value"]
            if all(e["metric_value"] == val_reference for e in history[key]):
                alerts.append(event)
                history[key].clear() # On vide pour éviter de spammer
                
    return alerts


def detect_rogue_device(events: list[dict], known_devices: set[str]) -> list[dict]:
    """Voir énoncé Partie 6, Exercice 6.3."""
    alerts = []
    for event in events:
        if event["device_id"] not in known_devices:
            alerts.append(event)
    return alerts


def detect_event_storm(events: list[dict], window_events: int = 20, max_per_device: int = 8):
    """Voir énoncé Partie 6, Exercice 6.4."""
    from collections import deque
    alerts = []
    
    # deque avec maxlen garde automatiquement que les X derniers éléments (fenêtre glissante)
    fenetre = deque(maxlen=window_events)

    for event in events:
        device = event["device_id"]
        fenetre.append(device)
        
        # On compte combien de fois cet appareil est dans la fenêtre actuelle
        if fenetre.count(device) > max_per_device:
            alerts.append(event)
            
    return alerts


# ============================================================
# PARTIE 8 — PSEUDONYMISATION HMAC
# ============================================================

def naive_hash_device_id(name: str) -> str:
    """Voir énoncé Partie 8, Exercice 8.1."""
    import hashlib
    # On hache le nom avec SHA-256 et on garde les 20 premiers caractères
    return hashlib.sha256(name.encode('utf-8')).hexdigest()[:20]


def hmac_pseudonymize(protocol: str, name: str, secret: bytes) -> str:
    """Voir énoncé Partie 8, Exercice 8.2."""
    
    message = f"{protocol}:{name}".encode('utf-8')
    
    
    return hmac_lib.new(secret, message, hashlib.sha256).hexdigest()[:20]


def dictionary_attack(observed_hashes: set[str], dictionary: list[str], hash_fn) -> dict:
    """Voir énoncé Partie 8, Exercice 8.3."""
    cracked = {}
    for guess in dictionary:
        
        guess_hash = hash_fn(guess)
        
        if guess_hash in observed_hashes:
            cracked[guess_hash] = guess
    return cracked


# ============================================================
# PARTIE 9 — DÉTECTION PAR ENTROPIE (canaux cachés)
# ============================================================

def shannon_entropy(s: str) -> float:
    """Voir énoncé Partie 9, Exercice 9.1."""
    if not s:
        return 0.0
        
    
    comptage = Counter(s)
    longueur = len(s)
    entropie = 0.0
    
    for compte in comptage.values():
        p_c = compte / longueur
        entropie -= p_c * math.log2(p_c)
        
    return entropie


def detect_high_entropy_unknown(events: list[dict], threshold: float = 4.5, min_length: int = 8) -> list[dict]:
    """Voir énoncé Partie 9, Exercice 9.2."""
    alerts = []
    for event in events:
        
        if event["metric_name"].startswith("unknown_") and event["metric_value"] is None:
            
            original_key = event["metric_name"][8:]
            
            
            raw_val = event.get("raw", {}).get("payload", {}).get(original_key)
            
            
            if isinstance(raw_val, str) and len(raw_val) >= min_length:
                if shannon_entropy(raw_val) > threshold:
                    alerts.append(event)
    return alerts


# ============================================================
# PARTIE 10 — EXTENSION MITRE (A10-A15)
# ============================================================

MITRE_ARTIFACT_LABELS = {
    "unmapped_linux_cmd": "A10 Privilege Escalation",
    "unmapped_net_cmd": "A11 Reverse Shell",
    "unmapped_persist_cmd": "A12 Persistence Cron/Systemd",
    "unmapped_cred_access": "A13 Credential Access",
    "unmapped_download_cmd": "A14 Command and Control / Dropper",
    "unmapped_lateral_cmd": "A15 Lateral Movement",
}


def detect_mitre_artifact(events: list[dict]) -> list[dict]:
    """Voir énoncé Partie 10, Exercice 10.1."""
    alerts = []
    for event in events:
        if event["metric_name"].startswith("unknown_"):
            
            original_key = event["metric_name"][8:]
            
            if original_key in MITRE_ARTIFACT_LABELS:
                
                event["mitre_tactic"] = MITRE_ARTIFACT_LABELS[original_key]
                alerts.append(event)
    return alerts


# ============================================================
# PARTIE 11 — PIPELINE COMPLET ET ÉVALUATION À GRANDE ÉCHELLE
# ============================================================

def run_pipeline(file_path: str, protocol: str, known_devices: set) -> dict:
    """Voir énoncé Partie 11, Exercice 11.1 et 11.2"""
    events = []
    
    # 1. Parsing & Normalisation
    with open(file_path, encoding='utf-8') as f:
        for line in f:
            if protocol == "zigbee":
                p = parse_zigbee_line(line)
                if p: events.extend(normalize_zigbee(p))
            elif protocol == "zwave":
                p = parse_zwave_line(line)
                if p: events.extend(normalize_zwave(p))
                
    total_brut = len(events)
    unknown_count = sum(1 for e in events if e.get("metric_name", "").startswith("unknown_"))
    
    # 2. Filtre Deadband (on utilise delta=1.0)
    events_filtres = deadband_filter(events, delta=1.0)
    
    # 3. Détections sur les événements filtrés
    return {
        "Evenements normalises (brut)": total_brut,
        "dont unknown_*": f"{unknown_count} ({(unknown_count/total_brut)*100:.1f} %)",
        "Evenements apres deadband": f"{len(events_filtres)} ({((total_brut-len(events_filtres))/total_brut)*100:.1f} % filtre)",
        "Alertes Power Surge": len(detect_power_surge(events_filtres)),
        "Alertes Replay": len(detect_replay(events_filtres)),
        "Alertes Rogue Device": len(detect_rogue_device(events_filtres, known_devices)),
        "Alertes Event Storm": len(detect_event_storm(events_filtres)),
        "Alertes entropie": len(detect_high_entropy_unknown(events_filtres)),
        "Alertes MITRE": len(detect_mitre_artifact(events_filtres))
    }

