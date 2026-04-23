import os
import csv
import random
import urllib.parse
from pathlib import Path

# =========================================================
# CONFIG
# =========================================================
BASE_DIR = Path(__file__).resolve().parent
PAYLOAD_DIR = BASE_DIR / "payloads"
TEMPLATE_FILE = BASE_DIR / "attack_templates.csv"
OUTPUT_DIR = BASE_DIR / "data_processed"
# Save custom dataset separately so it can later be merged with your existing master dataset
OUTPUT_FILE = BASE_DIR.parent / "data_raw" / "custom_dataset.csv"

random.seed(42)

# =========================================================
# HELPERS
# =========================================================
def load_templates(template_file):
    templates = []
    with open(template_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            templates.append(row)
    return templates


def load_payloads(payload_dir):
    payload_map = {}

    for file in payload_dir.glob("*.txt"):
        attack_type = file.stem.strip().lower()
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]
            payload_map[attack_type] = lines

    return payload_map


def apply_payload(template, payload):
    query = template["query_template"].replace("__PAYLOAD__", payload)
    body = template["body_template"].replace("__PAYLOAD__", payload)

    full_request = f"{template['method']} {template['path']}"

    if query:
        full_request += f"?{query}"

    if body:
        full_request += f" BODY:{body}"

    return full_request


def create_benign_samples(count=200):
    benign = []
    paths = ["/", "/home", "/login", "/products", "/about", "/contact"]
    queries = [
        "id=10",
        "page=home",
        "search=laptop",
        "category=electronics",
        "user=admin",
    ]

    for _ in range(count):
        path = random.choice(paths)
        query = random.choice(queries)
        request = f"GET {path}?{query}"
        benign.append({
            "attack_type": "benign",
            "request": request,
            "label": 0,
        })

    return benign


# =========================================================
# MAIN DATASET GENERATOR
# =========================================================
def build_dataset():
    if not PAYLOAD_DIR.exists():
        raise FileNotFoundError(f"Payload directory not found: {PAYLOAD_DIR}")

    if not TEMPLATE_FILE.exists():
        raise FileNotFoundError(f"Template file not found: {TEMPLATE_FILE}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    templates = load_templates(TEMPLATE_FILE)
    payload_map = load_payloads(PAYLOAD_DIR)

    dataset = []

    for template in templates:
        attack_type = template["attack_type"].strip().lower()

        if attack_type not in payload_map:
            print(f"[WARNING] No payload file found for: {attack_type}")
            continue

        payloads = payload_map[attack_type]

        for payload in payloads:
            raw_request = apply_payload(template, payload)
            encoded_request = urllib.parse.quote(raw_request, safe="/:?=& ")

            dataset.append({
                "attack_type": attack_type,
                "payload": payload,
                "request": raw_request,
                "encoded_request": encoded_request,
                "label": 1,
            })

    # add benign traffic
    dataset.extend(create_benign_samples())

    # save CSV
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "attack_type",
                "payload",
                "request",
                "encoded_request",
                "label",
            ],
        )
        writer.writeheader()
        writer.writerows(dataset)

    print("=" * 60)
    print("CUSTOM DATASET CREATED SUCCESSFULLY")
    print(f"Saved to: {OUTPUT_FILE}")
    print(f"Total samples: {len(dataset)}")
    print("=" * 60)


if __name__ == "__main__":
    build_dataset()
