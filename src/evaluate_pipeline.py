from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from pyspark.ml import PipelineModel
from pyspark.sql import SparkSession, functions as F

from train_pipeline import (
    apply_prediction_threshold,
    build_metric_comparison,
    evaluate_predictions,
    load_baseline_metrics,
)


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]

    parser = argparse.ArgumentParser(
        description="Evaluate the saved PySpark WAF pipeline on a reproducible test split."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=project_root,
        help="Root folder of the PySpark_WAF_Project.",
    )
    parser.add_argument(
        "--input-name",
        default="master_dataset",
        help="Folder name of the processed Parquet dataset under data_processed/.",
    )
    parser.add_argument(
        "--model-name",
        default="waf_detection_pipeline",
        help="Folder name of the saved Spark pipeline model under model/.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed used to reproduce the train/test split.",
    )
    parser.add_argument(
        "--prediction-threshold",
        type=float,
        default=0.70,
        help="Probability threshold used to mark a request as malicious.",
    )
    return parser.parse_args()


def save_json(path: Path, payload: dict[str, object]) -> None:
    # Reports are saved outside the model folder so the model folder stays clean.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_single_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    # These files are easy to open directly in Excel or VS Code after evaluation.
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def dataframe_rows(df, fieldnames: list[str]) -> list[dict[str, object]]:
    return [{field: row[field] for field in fieldnames} for row in df.select(*fieldnames).collect()]


def choose_recommended_threshold(threshold_rows: list[dict[str, object]]) -> dict[str, object]:
    # This project cares most about reducing false positives on real traffic.
    # First keep only thresholds that stay very close to the lowest false-positive rate.
    # Then pick the one with the strongest F1 and the fewest false negatives.
    minimum_false_positive_rate = min(float(row["false_positive_rate"]) for row in threshold_rows)
    false_positive_tolerance = max(minimum_false_positive_rate * 0.10, 1e-9)
    candidate_rows = [
        row
        for row in threshold_rows
        if float(row["false_positive_rate"]) <= minimum_false_positive_rate + false_positive_tolerance
    ]
    return max(
        candidate_rows,
        key=lambda row: (
            float(row["f1"]),
            -float(row["false_negative_rate"]),
            -float(row["false_positive_count"]),
            float(row["threshold"]),
        ),
    )


def main() -> None:
    args = parse_args()
    project_root = args.project_root.resolve()
    data_path = project_root / "data_processed" / args.input_name
    model_dir = project_root / "model" / args.model_name
    report_dir = project_root / "reports" / "evaluation"
    spark_report_dir = report_dir / "spark_outputs"
    metrics_path = report_dir / f"{args.model_name}_evaluation.json"
    comparison_path = report_dir / f"{args.model_name}_evaluation_comparison.json"
    confusion_dir = spark_report_dir / f"{args.model_name}_confusion_matrix"
    predictions_dir = spark_report_dir / f"{args.model_name}_evaluation_predictions"
    misclassified_dir = spark_report_dir / f"{args.model_name}_misclassified_examples"
    false_positive_dir = spark_report_dir / f"{args.model_name}_false_positive_analysis"
    false_negative_dir = spark_report_dir / f"{args.model_name}_false_negative_analysis"
    false_positive_csv_path = report_dir / "false_positives.csv"
    false_negative_csv_path = report_dir / "false_negatives.csv"
    misclassified_csv_path = report_dir / "misclassified_examples.csv"
    threshold_comparison_csv_path = report_dir / "threshold_comparison.csv"

    spark = SparkSession.builder.appName("EvaluateWAFPipeline").master("local[*]").getOrCreate()
    spark.sparkContext.setLogLevel("WARN")

    before_metrics = load_baseline_metrics(metrics_path, comparison_path)

    df = (
        spark.read.parquet(str(data_path))
        .select("request", "label", "source", "attack_type")
        .dropna(subset=["request", "label"])
        .dropDuplicates(["request", "label"])
    )

    _, test_df = df.randomSplit([0.8, 0.2], seed=args.seed)

    model = PipelineModel.load(str(model_dir))
    raw_predictions = model.transform(test_df).cache()
    predictions = apply_prediction_threshold(raw_predictions, args.prediction_threshold).cache()

    metrics = evaluate_predictions(predictions)
    metrics["test_rows"] = int(test_df.count())
    metrics["dataset_path"] = str(data_path)
    metrics["model_path"] = str(model_dir)
    metrics["prediction_threshold"] = float(args.prediction_threshold)

    # This checks a few practical thresholds so we can recommend one instead of guessing.
    threshold_candidates = sorted({0.60, 0.65, 0.70, 0.75, round(float(args.prediction_threshold), 2)})
    threshold_rows: list[dict[str, object]] = []
    for threshold_value in threshold_candidates:
        threshold_predictions = apply_prediction_threshold(raw_predictions, threshold_value).cache()
        threshold_metrics = evaluate_predictions(threshold_predictions)
        threshold_rows.append(
            {
                "threshold": float(threshold_value),
                "accuracy": float(threshold_metrics["accuracy"]),
                "weighted_precision": float(threshold_metrics["weighted_precision"]),
                "weighted_recall": float(threshold_metrics["weighted_recall"]),
                "f1": float(threshold_metrics["f1"]),
                "false_positive_count": int(threshold_metrics["false_positive_count"]),
                "false_negative_count": int(threshold_metrics["false_negative_count"]),
                "false_positive_rate": float(threshold_metrics["false_positive_rate"]),
                "false_negative_rate": float(threshold_metrics["false_negative_rate"]),
            }
        )
        threshold_predictions.unpersist()

    recommended_threshold_row = choose_recommended_threshold(threshold_rows)
    metrics["recommended_threshold"] = float(recommended_threshold_row["threshold"])

    save_json(metrics_path, metrics)
    save_json(comparison_path, build_metric_comparison(before_metrics, metrics))
    write_single_csv(
        threshold_comparison_csv_path,
        [
            "threshold",
            "accuracy",
            "weighted_precision",
            "weighted_recall",
            "f1",
            "false_positive_count",
            "false_negative_count",
            "false_positive_rate",
            "false_negative_rate",
        ],
        threshold_rows,
    )

    (
        predictions.groupBy("label", "prediction")
        .count()
        .orderBy("label", "prediction")
        .write.mode("overwrite")
        .option("header", True)
        .csv(str(confusion_dir))
    )

    (
        predictions.select(
            "request",
            "label",
            "prediction",
            "probability_malicious",
            "rule_based_malicious",
            "rule_based_safe",
            "rule_reason",
            "source",
            "attack_type",
        )
        .limit(250)
        .write.mode("overwrite")
        .option("header", True)
        .csv(str(predictions_dir))
    )

    error_df = (
        predictions.withColumn(
            "error_type",
            F.when((F.col("label") == 0) & (F.col("prediction") == 1), F.lit("false_positive"))
            .when((F.col("label") == 1) & (F.col("prediction") == 0), F.lit("false_negative"))
            .otherwise(F.lit("correct")),
        )
        .filter(F.col("error_type") != "correct")
    )

    (
        error_df.select(
            "request",
            "label",
            "prediction",
            "probability_malicious",
            "rule_based_malicious",
            "rule_based_safe",
            "rule_reason",
            "source",
            "attack_type",
            "error_type",
        )
        .write.mode("overwrite")
        .option("header", True)
        .csv(str(misclassified_dir))
    )

    (
        predictions.filter((F.col("label") == 0) & (F.col("prediction") == 1))
        .withColumn("request_method", F.regexp_extract("request", r"^([A-Z]+)", 1))
        .withColumn("request_path", F.regexp_extract("request", r"^[A-Z]+\s+(\S+)", 1))
        .withColumn("request_body", F.regexp_extract("request", r"(?s)\n\n(.*)$", 1))
        .withColumn("estimated_form_pair_count", F.when(F.length("request_body") > 0, F.size(F.split("request_body", "&"))).otherwise(F.lit(0)))
        .withColumn(
            "contains_common_benign_param",
            F.when(
                F.col("request").rlike(r"(?i)(^|[?&\n])(username|password|email|name|message|product_id|quantity|address|phone|city|page|id|qty|item)="),
                F.lit(1),
            ).otherwise(F.lit(0)),
        )
        .select(
            "request",
            "probability_malicious",
            "rule_based_safe",
            "rule_reason",
            "source",
            "attack_type",
            "request_method",
            "request_path",
            "estimated_form_pair_count",
            "contains_common_benign_param",
        )
        .write.mode("overwrite")
        .option("header", True)
        .csv(str(false_positive_dir))
    )

    (
        predictions.filter((F.col("label") == 1) & (F.col("prediction") == 0))
        .select(
            "request",
            "probability_malicious",
            "rule_reason",
            "source",
            "attack_type",
        )
        .write.mode("overwrite")
        .option("header", True)
        .csv(str(false_negative_dir))
    )

    false_positive_rows = dataframe_rows(
        predictions.filter((F.col("label") == 0) & (F.col("prediction") == 1))
        .orderBy(F.desc("probability_malicious")),
        [
            "request",
            "probability_malicious",
            "rule_based_malicious",
            "rule_based_safe",
            "rule_reason",
            "source",
            "attack_type",
        ],
    )
    false_negative_rows = dataframe_rows(
        predictions.filter((F.col("label") == 1) & (F.col("prediction") == 0))
        .orderBy("probability_malicious"),
        [
            "request",
            "probability_malicious",
            "rule_based_malicious",
            "rule_based_safe",
            "rule_reason",
            "source",
            "attack_type",
        ],
    )
    misclassified_rows = dataframe_rows(
        error_df.orderBy(F.desc("probability_malicious")),
        [
            "request",
            "label",
            "prediction",
            "probability_malicious",
            "rule_based_malicious",
            "rule_based_safe",
            "rule_reason",
            "source",
            "attack_type",
            "error_type",
        ],
    )

    write_single_csv(
        false_positive_csv_path,
        [
            "request",
            "probability_malicious",
            "rule_based_malicious",
            "rule_based_safe",
            "rule_reason",
            "source",
            "attack_type",
        ],
        false_positive_rows,
    )
    write_single_csv(
        false_negative_csv_path,
        [
            "request",
            "probability_malicious",
            "rule_based_malicious",
            "rule_based_safe",
            "rule_reason",
            "source",
            "attack_type",
        ],
        false_negative_rows,
    )
    write_single_csv(
        misclassified_csv_path,
        [
            "request",
            "label",
            "prediction",
            "probability_malicious",
            "rule_based_malicious",
            "rule_based_safe",
            "rule_reason",
            "source",
            "attack_type",
            "error_type",
        ],
        misclassified_rows,
    )

    print("\nEvaluation complete")
    print("-------------------")
    print(f"Test rows: {metrics['test_rows']}")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Weighted precision: {metrics['weighted_precision']:.4f}")
    print(f"Weighted recall: {metrics['weighted_recall']:.4f}")
    print(f"F1 score: {metrics['f1']:.4f}")
    print(f"Area under ROC: {metrics['area_under_roc']:.4f}")
    print(f"Area under PR: {metrics['area_under_pr']:.4f}")
    print(f"False positive count: {metrics['false_positive_count']}")
    print(f"False positive rate: {metrics['false_positive_rate']:.4f}")
    print(f"False negative count: {metrics['false_negative_count']}")
    print(f"False negative rate: {metrics['false_negative_rate']:.4f}")
    print(f"Prediction threshold: {metrics['prediction_threshold']:.2f}")
    print(f"Recommended threshold from sweep: {metrics['recommended_threshold']:.2f}")
    if before_metrics is not None:
        comparison = build_metric_comparison(before_metrics, metrics)
        false_positive_delta = comparison["delta"]["false_positive_count"]
        if false_positive_delta < 0:
            print(f"False positives improved by {-int(false_positive_delta)} compared with the previous baseline.")
        elif false_positive_delta > 0:
            print(f"False positives increased by {int(false_positive_delta)} compared with the previous baseline.")
        else:
            print("False positive count stayed the same as the previous baseline.")
    print(f"Saved evaluation metrics to: {metrics_path}")
    print(f"Saved before-vs-after comparison to: {comparison_path}")
    print(f"Saved threshold comparison CSV to: {threshold_comparison_csv_path}")
    print(f"Saved confusion matrix CSV to: {confusion_dir}")
    print(f"Saved evaluation predictions CSV to: {predictions_dir}")
    print(f"Saved misclassified examples CSV to: {misclassified_dir}")
    print(f"Saved false positive analysis CSV to: {false_positive_dir}")
    print(f"Saved false negative analysis CSV to: {false_negative_dir}")
    print(f"Saved single-file false positives CSV to: {false_positive_csv_path}")
    print(f"Saved single-file false negatives CSV to: {false_negative_csv_path}")
    print(f"Saved single-file misclassified CSV to: {misclassified_csv_path}")

    predictions.unpersist()
    raw_predictions.unpersist()
    spark.stop()


if __name__ == "__main__":
    main()
