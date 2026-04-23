from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from pyspark.sql import DataFrame, SparkSession, functions as F


HTTP_METHOD_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)(?:\s+(HTTP/\d(?:\.\d)?))?$",
    re.IGNORECASE,
)


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]

    parser = argparse.ArgumentParser(
        description="Build a canonical master dataset from the project's raw HTTP datasets."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=project_root,
        help="Root folder of the PySpark_WAF_Project.",
    )
    parser.add_argument(
        "--output-name",
        default="master_dataset",
        help="Folder name for the processed Parquet dataset under data_processed/.",
    )
    parser.add_argument(
        "--keep-duplicates",
        action="store_true",
        help="Keep duplicate (request, label) pairs instead of dropping them.",
    )
    return parser.parse_args()


def normalize_nullable(text: str | None) -> str | None:
    if text is None:
        return None
    cleaned = text.strip()
    if not cleaned or cleaned.lower() == "null":
        return None
    return cleaned


def md5_of_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonicalize_target(target: str) -> str:
    target = target.strip()
    if target.lower().startswith(("http://", "https://")):
        parsed = urlsplit(target)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path
    return target


def canonicalize_request_line(request_line: str, default_version: str = "HTTP/1.1") -> str | None:
    request_line = normalize_nullable(request_line)
    if request_line is None:
        return None

    match = HTTP_METHOD_RE.match(request_line)
    if not match:
        return None

    method, target, version = match.groups()
    canonical_target = canonicalize_target(target)
    return f"{method.upper()} {canonical_target} {version or default_version}"


def combine_request_and_body(request_line: str | None, body: str | None) -> str | None:
    if request_line is None:
        return None
    body = normalize_nullable(body)
    if body is None:
        return request_line
    return f"{request_line}\n\n{body}"


def parse_dataset1_record(row: dict[str, str], source_name: str) -> dict[str, object] | None:
    label_name = normalize_nullable(row.get(""))
    method = normalize_nullable(row.get("Method"))
    url_field = normalize_nullable(row.get("URL"))

    if label_name is None or method is None or url_field is None:
        return None

    label_lookup = {"normal": 0, "anomalous": 1}
    label = label_lookup.get(label_name.lower())
    if label is None:
        return None

    version = "HTTP/1.1"
    target = url_field
    parts = url_field.rsplit(" ", 1)
    if len(parts) == 2 and parts[1].startswith("HTTP/"):
        target, version = parts

    request_line = canonicalize_request_line(f"{method.upper()} {target} {version}")
    body = normalize_nullable(row.get("content"))
    request = combine_request_and_body(request_line, body)
    if request is None:
        return None

    return {
        "request": request,
        "raw_request": request,
        "label": label,
        "source": source_name,
        "attack_type": "normal" if label == 0 else "public_attack",
    }


def load_dataset1(path: Path, source_name: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            record = parse_dataset1_record(row, source_name)
            if record is not None:
                records.append(record)
    return records


def load_custom_dataset(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            label_text = normalize_nullable(row.get("label"))
            if label_text not in {"0", "1"}:
                continue

            preferred_request = normalize_nullable(row.get("encoded_request")) or normalize_nullable(row.get("request"))
            canonical_request = None
            if preferred_request is not None:
                if " HTTP/" in preferred_request:
                    canonical_request = canonicalize_request_line(preferred_request)
                else:
                    canonical_request = canonicalize_request_line(f"{preferred_request} HTTP/1.1")

            if canonical_request is None:
                continue

            records.append(
                {
                    "request": canonical_request,
                    "raw_request": normalize_nullable(row.get("request")) or canonical_request,
                    "label": int(label_text),
                    "source": "custom_dataset",
                    "attack_type": normalize_nullable(row.get("attack_type")) or ("normal" if label_text == "0" else "custom_attack"),
                }
            )
    return records


def parse_quoted_line(raw_line: str) -> str:
    line = raw_line.rstrip("\r\n")
    if len(line) >= 2 and line[0] == '"' and line[-1] == '"':
        line = line[1:-1]
    return line.replace('""', '"')


def parse_dataset2(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    block: list[str] = []

    def flush_block(lines: list[str]) -> None:
        label = 1
        request_line: str | None = None
        body_lines: list[str] = []
        inside_body = False

        for line in lines:
            if line.lower().startswith("class:"):
                class_name = line.split(":", 1)[1].strip().lower()
                label = 0 if class_name == "normal" else 1
                continue

            canonical_line = canonicalize_request_line(line)
            if canonical_line is not None:
                request_line = canonical_line
                continue

            if request_line is None:
                continue

            if line == "":
                inside_body = True
                continue

            if inside_body:
                body_value = normalize_nullable(line)
                if body_value is not None:
                    body_lines.append(body_value)

        request = combine_request_and_body(request_line, "\n".join(body_lines) if body_lines else None)
        if request is None:
            return

        records.append(
            {
                "request": request,
                "raw_request": request,
                "label": label,
                "source": "dataset2",
                "attack_type": "normal" if label == 0 else "public_attack",
            }
        )

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = parse_quoted_line(raw_line)
            if line.startswith("Start - Id:"):
                block = []
                continue
            if line.startswith("End - Id:"):
                flush_block(block)
                block = []
                continue
            block.append(line)

    if block:
        flush_block(block)
    return records


def parse_dataset3(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    request_line: str | None = None
    body_lines: list[str] = []
    inside_body = False

    def flush_request(current_request_line: str | None, current_body_lines: list[str]) -> None:
        request = combine_request_and_body(current_request_line, "\n".join(current_body_lines) if current_body_lines else None)
        if request is None:
            return
        records.append(
            {
                "request": request,
                "raw_request": request,
                "label": 1,
                "source": "dataset3",
                "attack_type": "public_attack",
            }
        )

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = parse_quoted_line(raw_line)
            canonical_line = canonicalize_request_line(line)
            if canonical_line is not None:
                if request_line is not None:
                    flush_request(request_line, body_lines)
                request_line = canonical_line
                body_lines = []
                inside_body = False
                continue

            if request_line is None:
                continue

            if line == "":
                inside_body = True
                continue

            if inside_body:
                body_value = normalize_nullable(line)
                if body_value is not None:
                    body_lines.append(body_value)

    if request_line is not None:
        flush_request(request_line, body_lines)
    return records


def write_jsonl(path: Path, records: list[dict[str, object]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")
    return path


def load_json_dataset(spark: SparkSession, path: Path) -> DataFrame:
    return spark.read.json(str(path))


def standardize(df: DataFrame) -> DataFrame:
    # This keeps the request text consistent before we merge sources.
    return (
        df.withColumn("request", F.regexp_replace(F.col("request"), r"\r\n?", "\n"))
        .withColumn("raw_request", F.regexp_replace(F.col("raw_request"), r"\r\n?", "\n"))
        .withColumn("label", F.col("label").cast("int"))
        .filter(F.col("request").isNotNull() & (F.length(F.trim(F.col("request"))) > 0))
        .filter(F.col("label").isNotNull())
    )


def print_summary(df: DataFrame, title: str) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    print(f"Total rows: {df.count()}")
    df.groupBy("source", "label").count().orderBy("source", "label").show(truncate=False)


def main() -> None:
    args = parse_args()
    project_root = args.project_root.resolve()
    raw_dir = project_root / "data_raw"
    processed_dir = project_root / "data_processed"
    staging_dir = processed_dir / "_staging"
    output_dir = processed_dir / args.output_name
    metadata_path = processed_dir / f"{args.output_name}_metadata.json"

    dataset1_path = raw_dir / "dataset1.csv"
    csic_path = raw_dir / "csic_database.csv"
    custom_path = raw_dir / "custom_dataset.csv"
    dataset2_path = raw_dir / "dataset2.csv"
    dataset3_path = raw_dir / "dataset3.csv"

    excluded_sources: list[dict[str, str]] = []
    included_records: dict[str, list[dict[str, object]]] = {}

    if dataset1_path.exists():
        included_records["dataset1"] = load_dataset1(dataset1_path, "dataset1")

    if csic_path.exists():
        if dataset1_path.exists() and md5_of_file(dataset1_path) == md5_of_file(csic_path):
            excluded_sources.append({"source": "csic_database", "reason": "exact_duplicate_of_dataset1"})
        else:
            included_records["csic_database"] = load_dataset1(csic_path, "csic_database")

    if custom_path.exists():
        included_records["custom_dataset"] = load_custom_dataset(custom_path)

    dataset2_records = parse_dataset2(dataset2_path) if dataset2_path.exists() else []
    dataset3_records = parse_dataset3(dataset3_path) if dataset3_path.exists() else []
    dataset2_signature = {(record["request"], record["label"]) for record in dataset2_records}
    dataset3_signature = {(record["request"], record["label"]) for record in dataset3_records}

    if dataset2_records:
        included_records["dataset2"] = dataset2_records

    if dataset3_records:
        if dataset3_signature == dataset2_signature and dataset2_signature:
            excluded_sources.append({"source": "dataset3", "reason": "exact_duplicate_of_dataset2_after_canonicalization"})
        else:
            included_records["dataset3"] = dataset3_records

    spark = SparkSession.builder.appName("BuildMasterDataset").master("local[*]").getOrCreate()
    spark.sparkContext.setLogLevel("WARN")

    source_dfs: list[DataFrame] = []
    source_row_counts: dict[str, int] = {}
    for source_name, records in included_records.items():
        source_row_counts[source_name] = len(records)
        json_path = write_jsonl(staging_dir / f"{source_name}.jsonl", records)
        source_dfs.append(standardize(load_json_dataset(spark, json_path)))

    if not source_dfs:
        raise FileNotFoundError("No supported datasets were found in data_raw.")

    combined_df = source_dfs[0]
    for df in source_dfs[1:]:
        combined_df = combined_df.unionByName(df)

    print_summary(combined_df, "Combined dataset before deduplication")

    final_df = combined_df if args.keep_duplicates else combined_df.dropDuplicates(["request", "label"])

    print_summary(final_df, "Final canonical master dataset")

    final_df.write.mode("overwrite").parquet(str(output_dir))
    (
        final_df.select("request", "label", "source", "attack_type")
        .limit(100)
        .write.mode("overwrite")
        .option("header", True)
        .csv(str(processed_dir / f"{args.output_name}_sample_csv"))
    )

    # This records the final class balance so we can check imbalance before training.
    final_label_distribution = {
        int(row["label"]): int(row["count"])
        for row in final_df.groupBy("label").count().collect()
    }
    # This records the attack-type mix so we can audit what kinds of attacks reached the trainer.
    final_attack_type_distribution = {
        str(row["attack_type"]): int(row["count"])
        for row in final_df.groupBy("attack_type").count().collect()
    }
    metadata = {
        "output_path": str(output_dir),
        "included_sources": sorted(source_row_counts.keys()),
        "excluded_sources": excluded_sources,
        "raw_record_counts": source_row_counts,
        "final_total_rows": int(final_df.count()),
        "final_label_distribution": final_label_distribution,
        "final_attack_type_distribution": final_attack_type_distribution,
        "final_imbalance_ratio_malicious_to_normal": float(
            final_label_distribution.get(1, 0) / max(final_label_distribution.get(0, 1), 1)
        ),
        "kept_duplicates": args.keep_duplicates,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"\nSaved master dataset to: {output_dir}")
    print(f"Saved metadata to: {metadata_path}")

    spark.stop()


if __name__ == "__main__":
    main()
