from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from pyspark.ml import PipelineModel
from pyspark.sql import SparkSession

from train_pipeline import apply_prediction_threshold


HTTP_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "OPTIONS ", "HEAD ")


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]

    parser = argparse.ArgumentParser(
        description="Run the saved WAF pipeline on unseen logs and write predictions as CSV."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=project_root,
        help="Root folder of the PySpark_WAF_Project.",
    )
    parser.add_argument(
        "--model-name",
        default="waf_detection_pipeline",
        help="Folder name of the saved Spark pipeline model under model/.",
    )
    parser.add_argument(
        "--input-path",
        type=Path,
        default=project_root / "demo_files" / "new_unseen_logs.log",
        help="Path to a raw log file or CSV containing unseen requests.",
    )
    parser.add_argument(
        "--output-name",
        default="predictions_output",
        help="Folder name created under demo_files/ for the prediction CSV output.",
    )
    parser.add_argument(
        "--prediction-threshold",
        type=float,
        default=0.70,
        help="Probability threshold used to mark a request as malicious.",
    )
    return parser.parse_args()


def parse_request_log(path: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current_request: str | None = None
    body_lines: list[str] = []
    inside_body = False

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\r\n")
            stripped = line.strip().strip('"')

            if not stripped:
                if current_request is not None:
                    inside_body = True
                continue

            upper = stripped.upper()
            if upper.startswith(HTTP_METHODS):
                if current_request is not None:
                    request = current_request
                    if body_lines:
                        request = f"{request}\n\n" + "\n".join(body_lines)
                    records.append({"request": request})

                current_request = stripped
                body_lines = []
                inside_body = False
                continue

            if current_request is not None and inside_body:
                body_lines.append(stripped)

    if current_request is not None:
        request = current_request
        if body_lines:
            request = f"{request}\n\n" + "\n".join(body_lines)
        records.append({"request": request})

    return records


def load_requests_from_csv(path: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            return records
        request_field = next((name for name in reader.fieldnames if name.lower() == "request"), None)
        if request_field is None:
            raise ValueError("CSV input must contain a 'request' column.")

        for row in reader:
            request = (row.get(request_field) or "").strip()
            if request:
                records.append({"request": request})
    return records


def write_jsonl(path: Path, records: list[dict[str, str]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")
    return path


def main() -> None:
    args = parse_args()
    project_root = args.project_root.resolve()
    input_path = args.input_path.resolve()
    model_dir = project_root / "model" / args.model_name
    output_dir = project_root / "demo_files" / args.output_name
    output_csv = output_dir / "predictions.csv"
    staging_path = project_root / "demo_files" / "_prediction_staging" / "requests.jsonl"

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    if input_path.suffix.lower() == ".csv":
        records = load_requests_from_csv(input_path)
    else:
        records = parse_request_log(input_path)

    if not records:
        raise ValueError(f"No requests were parsed from: {input_path}")

    spark = SparkSession.builder.appName("RunWAFPrediction").master("local[*]").getOrCreate()
    spark.sparkContext.setLogLevel("WARN")

    model = PipelineModel.load(str(model_dir))
    jsonl_path = write_jsonl(staging_path, records)
    requests_df = spark.read.json(str(jsonl_path))
    raw_predictions = model.transform(requests_df)
    predictions = apply_prediction_threshold(raw_predictions, args.prediction_threshold)

    rows = predictions.select(
        "request",
        "prediction",
        "probability_malicious",
        "rule_based_malicious",
        "rule_based_safe",
        "rule_reason",
    ).collect()
    output_dir.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["request", "prediction", "probability_malicious", "rule_based_malicious", "rule_based_safe", "rule_reason"])
        for row in rows:
            writer.writerow(
                [
                    row["request"],
                    int(row["prediction"]),
                    float(row["probability_malicious"]),
                    int(row["rule_based_malicious"]),
                    int(row["rule_based_safe"]),
                    row["rule_reason"],
                ]
            )

    prediction_counts: dict[int, int] = {}
    for row in rows:
        value = int(row["prediction"])
        prediction_counts[value] = prediction_counts.get(value, 0) + 1

    print("\nPrediction run complete")
    print("-----------------------")
    print(f"Input file: {input_path}")
    print(f"Parsed requests: {len(records)}")
    print(f"Prediction threshold: {args.prediction_threshold:.2f}")
    for prediction in sorted(prediction_counts):
        label_name = "Normal" if prediction == 0 else "Malicious"
        print(f"{label_name} ({prediction}): {prediction_counts[prediction]}")
    print(f"Saved prediction CSV to: {output_csv}")

    spark.stop()


if __name__ == "__main__":
    main()
