from __future__ import annotations

import argparse
import json
from pathlib import Path

from pyspark.ml import Pipeline
from pyspark.ml.classification import LogisticRegression
from pyspark.ml.evaluation import BinaryClassificationEvaluator, MulticlassClassificationEvaluator
from pyspark.ml.feature import HashingTF, IDF, RegexTokenizer, SQLTransformer, VectorAssembler
from pyspark.ml.functions import vector_to_array
from pyspark.sql import DataFrame, SparkSession, functions as F


HIGH_CONFIDENCE_SQL_REGEX = r"(?i)(?:'\s*or\s*'?[0-9a-z]+'?\s*=\s*'?[0-9a-z]+'?|\bor\s+1\s*=\s*1\b|\band\s+1\s*=\s*1\b|union\s+all?\s+select|union(?:%20|\s)+select|information_schema|xp_cmdshell|sleep\s*\(|benchmark\s*\()"
SQL_TAUTOLOGY_REGEX = r"(?i)(?:\bor\s+1\s*=\s*1\b|\band\s+1\s*=\s*1\b|(?:'|%27)\s*or\s*(?:'|%27)?[0-9a-z]+(?:'|%27)?\s*=\s*(?:'|%27)?[0-9a-z]+(?:'|%27)?)"
UNION_SELECT_REGEX = r"(?i)(?:union(?:%20|\s)+(?:all(?:%20|\s)+)?select)"
SQL_COMMENT_ATTACK_REGEX = r"(?i)(?:'|%27)\s*(?:--|#|/\*)"
HIGH_CONFIDENCE_XSS_REGEX = r"(?i)(?:<script|%3cscript|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|<img|svg/onload)"
HIGH_CONFIDENCE_CMD_REGEX = r"(?i)(?:&&|\|\||;\s*(?:whoami|ls|cat|curl|wget)|\$\(|`[^`]+`|/bin/|cmd\.exe|powershell|cat\s+/etc/passwd|whoami|wget\s|curl\s)"
HIGH_CONFIDENCE_TRAVERSAL_REGEX = r"(?i)(?:\.\./|\.\.\\|%2e%2e|%252e%252e|/etc/passwd|windows[/\\]system32|drivers[/\\]etc[/\\]hosts|boot\.ini|win\.ini)"
HIGH_CONFIDENCE_SSTI_REGEX = r"(?i)(?:\{\{|\}\}|%7b%7b|%7d%7d|\$\{|__import__|config\.|\{\{7\*7\}\})"
SAFE_SEARCH_REGEX = r"(?i)^get\s+/search\?(?:[^\s]*&)?q=[a-z0-9+._\-%]+\s+http/1\.1$"
SAFE_API_REGEX = r"(?i)^get\s+/api/[a-z0-9/_\-.]+\?(?:[^\s]*&)?(?:page|limit|offset|id)="
STRICT_SAFE_FORM_BODY_REGEX = r"(?i)^[a-z0-9_]+=[a-z0-9@._%+\-,/]+(&[a-z0-9_]+=[a-z0-9@._%+\-,/]+)*$"
SAFE_FORM_ENDPOINT_REGEX = r"(?i)^/(login|register|contact|checkout|profile|support|account/login|bookings/selectseats|bookings/payment|bookings/create|inquiries/create|reviews/create|members/create|events/create|events/edit)(?:$|/)"
BENIGN_PARAM_NAMES = [
    "username",
    "password",
    "email",
    "name",
    "message",
    "product_id",
    "quantity",
    "address",
    "phone",
    "city",
    "page",
    "id",
    "qty",
    "item",
    "mobile",
    "eventid",
    "selectedseatids",
    "paymenttype",
    "seatid",
    "bookingid",
    "memberid",
    "review",
    "rating",
    "subject",
    "description",
    "eventname",
    "venue",
    "date",
]
COMMON_BENIGN_PARAM_REGEX = "|".join(BENIGN_PARAM_NAMES)


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]

    parser = argparse.ArgumentParser(
        description="Train and save the PySpark WAF detection pipeline."
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
        help="Folder name to save the trained Spark pipeline model under model/.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for splitting and training.",
    )
    parser.add_argument(
        "--max-iter",
        type=int,
        default=100,
        help="Maximum iterations for Logistic Regression.",
    )
    parser.add_argument(
        "--num-features",
        type=int,
        default=8192,
        help="Number of hashing features for request tokens.",
    )
    parser.add_argument(
        "--prediction-threshold",
        type=float,
        default=0.70,
        help="Probability threshold used to mark a request as malicious.",
    )
    return parser.parse_args()


def to_sql_regex_literal(pattern: str) -> str:
    # Spark SQL strings need both backslashes and single quotes escaped before Java regex sees them.
    return pattern.replace("\\", "\\\\").replace("'", "''")


def build_feature_pipeline(feature_columns: list[str], args: argparse.Namespace) -> Pipeline:
    high_confidence_sql_regex = to_sql_regex_literal(HIGH_CONFIDENCE_SQL_REGEX)
    sql_tautology_regex = to_sql_regex_literal(SQL_TAUTOLOGY_REGEX)
    union_select_regex = to_sql_regex_literal(UNION_SELECT_REGEX)
    sql_comment_attack_regex = to_sql_regex_literal(SQL_COMMENT_ATTACK_REGEX)
    high_confidence_xss_regex = to_sql_regex_literal(HIGH_CONFIDENCE_XSS_REGEX)
    high_confidence_cmd_regex = to_sql_regex_literal(HIGH_CONFIDENCE_CMD_REGEX)
    high_confidence_traversal_regex = to_sql_regex_literal(HIGH_CONFIDENCE_TRAVERSAL_REGEX)
    high_confidence_ssti_regex = to_sql_regex_literal(HIGH_CONFIDENCE_SSTI_REGEX)
    safe_search_regex = to_sql_regex_literal(SAFE_SEARCH_REGEX)
    safe_api_regex = to_sql_regex_literal(SAFE_API_REGEX)
    strict_safe_form_body_regex = to_sql_regex_literal(STRICT_SAFE_FORM_BODY_REGEX)
    safe_form_endpoint_regex = to_sql_regex_literal(SAFE_FORM_ENDPOINT_REGEX)
    common_benign_param_regex = to_sql_regex_literal(COMMON_BENIGN_PARAM_REGEX)

    # This keeps parsed request pieces in columns so the model can reason about bodies and endpoints.
    request_normalizer = SQLTransformer(
        statement=r"""
        SELECT
            *,
            lower(request) AS request_lower,
            regexp_extract(lower(request), '(?s)\n\n(.*)$', 1) AS request_body,
            regexp_extract(lower(request), '^([a-z]+)', 1) AS request_method,
            regexp_extract(lower(request), '^[a-z]+\s+(\S+)', 1) AS request_target,
            regexp_extract(lower(request), '^[a-z]+\s+([^?\s]+)', 1) AS request_path,
            regexp_extract(lower(request), '^[a-z]+\s+[^?\s]+\?([^\s]+)', 1) AS request_query
        FROM __THIS__
        """
    )

    # These features keep strong attack signals and add safer form-submission hints for real app traffic.
    feature_builder = SQLTransformer(
        statement=rf"""
        SELECT
            *,
            CAST(length(request) AS DOUBLE) AS request_length,
            CAST(length(regexp_replace(request, '[^;|&`$<>(){{}}%=/#-]', '')) AS DOUBLE) AS suspicious_char_count,
            CAST(length(regexp_replace(request, '[^=]', '')) AS DOUBLE) AS equals_count,
            CAST(length(regexp_replace(request, '[^&]', '')) AS DOUBLE) AS ampersand_count,
            CAST(length(regexp_replace(request, '[^%]', '')) AS DOUBLE) AS percent_count,
            CAST(CASE WHEN request_lower RLIKE '^post\\s' THEN 0.05 ELSE 0.0 END AS DOUBLE) AS is_post,
            CAST(CASE WHEN request_lower RLIKE '^get\\s' THEN 1 ELSE 0 END AS DOUBLE) AS is_get,
            CAST(CASE WHEN instr(request, '?') > 0 THEN 1 ELSE 0 END AS DOUBLE) AS has_query_string,
            CAST(CASE WHEN instr(request, '\n\n') > 0 THEN 0.05 ELSE 0.0 END AS DOUBLE) AS has_body,
            CAST(CASE WHEN request_lower RLIKE '%[0-9a-f]{{2}}' THEN 1 ELSE 0 END AS DOUBLE) AS has_url_encoding,
            CAST(CASE WHEN request_lower RLIKE '(union|select|drop|insert|delete|update|sleep\\s*\\(|benchmark\\s*\\(|or\\s+1\\s*=\\s*1|and\\s+1\\s*=\\s*1|information_schema|xp_cmdshell)' THEN 1 ELSE 0 END AS DOUBLE) AS has_sql_pattern,
            CAST(CASE WHEN request_lower RLIKE '(<script|%3cscript|javascript:|onerror\\s*=|onload\\s*=|alert\\s*\\(|document\\.cookie|<img|svg/onload)' THEN 1 ELSE 0 END AS DOUBLE) AS has_xss_pattern,
            CAST(CASE WHEN request_lower RLIKE '(&&|\\|\\||;|\\$\\(|`|/bin/|cmd\\.exe|powershell|whoami|cat\\s+/etc/passwd|wget\\s|curl\\s)' THEN 1 ELSE 0 END AS DOUBLE) AS has_command_pattern,
            CAST(CASE WHEN request_lower RLIKE '(\\.\\./|\\.\\.\\\\|%2e%2e|%252e%252e|/etc/passwd|boot\\.ini|win\\.ini)' THEN 1 ELSE 0 END AS DOUBLE) AS has_traversal_pattern,
            CAST(CASE WHEN request_lower RLIKE '(\\{{\\{{|\\}}\\}}|%7b%7b|%7d%7d|\\$\\{{|__import__|config\\.|\\{{\\{{7\\*7\\}}\\}})' THEN 1 ELSE 0 END AS DOUBLE) AS has_ssti_pattern,
            CAST(CASE WHEN request_lower RLIKE '{high_confidence_sql_regex}' THEN 1 ELSE 0 END AS DOUBLE) AS has_high_confidence_sql,
            CAST(CASE WHEN request_lower RLIKE '{sql_tautology_regex}' THEN 1 ELSE 0 END AS DOUBLE) AS has_sql_tautology,
            CAST(CASE WHEN request_lower RLIKE '{union_select_regex}' THEN 1 ELSE 0 END AS DOUBLE) AS has_union_select_pattern,
            CAST(CASE WHEN request_lower RLIKE '{sql_comment_attack_regex}' THEN 1 ELSE 0 END AS DOUBLE) AS has_sql_comment_attack,
            CAST(CASE WHEN request_lower RLIKE '{high_confidence_xss_regex}' THEN 1 ELSE 0 END AS DOUBLE) AS has_high_confidence_xss,
            CAST(CASE WHEN request_lower RLIKE '{high_confidence_cmd_regex}' THEN 1 ELSE 0 END AS DOUBLE) AS has_high_confidence_command,
            CAST(CASE WHEN request_lower RLIKE '{high_confidence_traversal_regex}' THEN 1 ELSE 0 END AS DOUBLE) AS has_high_confidence_traversal,
            CAST(CASE WHEN request_lower RLIKE '{high_confidence_ssti_regex}' THEN 1 ELSE 0 END AS DOUBLE) AS has_high_confidence_ssti,
            CAST(CASE WHEN request_lower RLIKE '^get /(home|about|contact|products|product|index)(\\?|\\s|/)' THEN 1 ELSE 0 END AS DOUBLE) AS has_navigation_path,
            CAST(CASE WHEN request_lower RLIKE '[?&]id=[0-9]+($|[&\\s])' THEN 1 ELSE 0 END AS DOUBLE) AS has_simple_numeric_id,
            CAST(CASE WHEN request_lower RLIKE '^post /login\\s' AND request_lower RLIKE 'username=' AND request_lower RLIKE 'password=' THEN 1 ELSE 0 END AS DOUBLE) AS has_login_fields,
            CAST(CASE WHEN request_path RLIKE '{safe_form_endpoint_regex}' THEN 1 ELSE 0 END AS DOUBLE) AS has_benign_form_endpoint,
            CAST(CASE WHEN request_lower RLIKE '^[a-z]+ /[^\\s]*[a-z0-9/_\\-.?=&%+]+ http/1\\.1(\\n\\n[a-z0-9_=&%+\\-.@ ]+)?$' THEN 1 ELSE 0 END AS DOUBLE) AS has_simple_benign_shape,
            CAST(CASE WHEN request_lower RLIKE '^get /[a-z0-9/_%\\-.]+\\.(jpg|jpeg|png|gif|css|js|ico)(\\?[a-z0-9_=&%\\-.]+)? http/1\\.1$' AND request_lower NOT RLIKE '(\\.jsp/|\\.php/|\\.asp/|\\.aspx/)' THEN 1 ELSE 0 END AS DOUBLE) AS has_static_asset_path,
            CAST(CASE WHEN request_body RLIKE '{strict_safe_form_body_regex}' THEN 1 ELSE 0 END AS DOUBLE) AS has_simple_form_body,
            CAST(CASE WHEN request_lower RLIKE '{safe_search_regex}' AND request_lower NOT RLIKE '(<script|union|select|drop|sleep\\s*\\(|benchmark\\s*\\(|;|\\$\\(|\\{{\\{{|\\.\\./)' THEN 1 ELSE 0 END AS DOUBLE) AS has_safe_search_request,
            CAST(CASE WHEN request_lower RLIKE '{safe_api_regex}' AND request_lower NOT RLIKE '(union|select|drop|<script|\\.\\./|;|\\$\\()' THEN 1 ELSE 0 END AS DOUBLE) AS has_safe_api_request,
            CAST(CASE WHEN request_path RLIKE '(?i)^/checkout(?:$|/)' AND request_body RLIKE '(^|&)(product_id|item|id)=' AND request_body RLIKE '(^|&)(quantity|qty)=' THEN 1 ELSE 0 END AS DOUBLE) AS has_checkout_fields,
            CAST(CASE WHEN request_lower RLIKE '^post /register\\s' AND request_body RLIKE '(^|&)email=' THEN 1 ELSE 0 END AS DOUBLE) AS has_register_fields,
            CAST(CASE WHEN request_lower RLIKE '^post /contact\\s' AND request_body RLIKE '(^|&)(name|message)=' THEN 1 ELSE 0 END AS DOUBLE) AS has_contact_fields,
            CAST(CASE WHEN request_path RLIKE '(?i)^/profile(?:$|/)' AND request_body RLIKE '(^|&)(name|email|phone|address|city)=' THEN 1 ELSE 0 END AS DOUBLE) AS has_profile_fields,
            CAST(CASE WHEN request_path RLIKE '(?i)^/support(?:$|/)' AND request_body RLIKE '(^|&)(name|email|message)=' THEN 1 ELSE 0 END AS DOUBLE) AS has_support_fields,
            CAST(length(request_body) AS DOUBLE) AS body_length,
            CAST(CASE WHEN length(request_body) > 0 THEN size(split(request_body, '&')) ELSE 0 END AS DOUBLE) AS form_key_value_pair_count,
            CAST(
                (CASE WHEN request_body RLIKE '(^|&)username=' OR request_lower RLIKE '[?&]username=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)password=' OR request_lower RLIKE '[?&]password=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)email=' OR request_lower RLIKE '[?&]email=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)name=' OR request_lower RLIKE '[?&]name=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)message=' OR request_lower RLIKE '[?&]message=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)product_id=' OR request_lower RLIKE '[?&]product_id=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)quantity=' OR request_lower RLIKE '[?&]quantity=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)address=' OR request_lower RLIKE '[?&]address=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)phone=' OR request_lower RLIKE '[?&]phone=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)city=' OR request_lower RLIKE '[?&]city=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)page=' OR request_lower RLIKE '[?&]page=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)id=' OR request_lower RLIKE '[?&]id=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)qty=' OR request_lower RLIKE '[?&]qty=' THEN 1 ELSE 0 END) +
                (CASE WHEN request_body RLIKE '(^|&)item=' OR request_lower RLIKE '[?&]item=' THEN 1 ELSE 0 END)
            AS DOUBLE) AS benign_param_name_count,
            CAST(CASE WHEN request_body RLIKE '(^|&)({common_benign_param_regex})=' OR request_lower RLIKE '[?&]({common_benign_param_regex})=' THEN 1 ELSE 0 END AS DOUBLE) AS has_common_benign_param,
            CAST(length(regexp_replace(request_body, '[^a-z0-9]', '')) AS DOUBLE) AS body_alphanumeric_count,
            CAST(length(regexp_replace(request_body, '[a-z0-9]', '')) AS DOUBLE) AS body_symbol_count,
            CAST(
                CASE
                    WHEN length(request_body) > 0
                    THEN CAST(length(regexp_replace(request_body, '[^a-z0-9]', '')) AS DOUBLE) /
                         CAST(greatest(length(regexp_replace(request_body, '[a-z0-9]', '')), 1) AS DOUBLE)
                    ELSE 0.0
                END
            AS DOUBLE) AS body_alphanumeric_to_symbol_ratio,
            CAST(CASE WHEN length(request_body) > 0 AND request_body RLIKE '^[a-z0-9_]+=[^&=]+(&[a-z0-9_]+=[^&=]+)*$' THEN 1 ELSE 0 END AS DOUBLE) AS has_form_urlencoded_shape,
            CAST(CASE WHEN length(request_body) > 0 AND request_body RLIKE '{strict_safe_form_body_regex}' THEN 1 ELSE 0 END AS DOUBLE) AS has_strict_safe_form_body,
            CAST(CASE WHEN length(request_body) > 0 AND request_body RLIKE '^[a-z0-9_]+=[^&=]+(&[a-z0-9_]+=[^&=]+)*$' AND length(regexp_replace(request_body, '[^=]', '')) = length(regexp_replace(request_body, '[^&]', '')) + 1 THEN 1 ELSE 0 END AS DOUBLE) AS has_balanced_form_pairs,
            CAST(CASE WHEN length(request_body) > 0 AND size(split(request_body, '&')) BETWEEN 1 AND 8 AND length(request_body) <= 240 THEN 1 ELSE 0 END AS DOUBLE) AS has_small_form_payload,
            CAST(CASE WHEN request_body RLIKE '(^|&)(name|message|email)=' THEN 1 ELSE 0 END AS DOUBLE) AS has_message_style_fields,
            CAST(CASE WHEN request_body RLIKE '(^|&)(address|city|phone)=' THEN 1 ELSE 0 END AS DOUBLE) AS has_profile_style_fields,
            CAST(
                CASE
                    WHEN request_lower RLIKE '^post\\s'
                        AND length(request_body) > 0
                        AND request_body RLIKE '{strict_safe_form_body_regex}'
                        AND size(split(request_body, '&')) BETWEEN 1 AND 8
                        AND (
                            request_body RLIKE '(^|&)({common_benign_param_regex})='
                            OR request_lower RLIKE '[?&]({common_benign_param_regex})='
                        )
                        AND request_lower NOT RLIKE '(<script|%3cscript|javascript:|onerror\\s*=|onload\\s*=|alert\\s*\\(|document\\.cookie|<img|svg/onload|&&|\\|\\||;\\s*(whoami|ls|cat|curl|wget)|\\$\\(|`[^`]+`|/bin/|cmd\\.exe|powershell|cat\\s+/etc/passwd|whoami|wget\\s|curl\\s|\\.\\./|\\.\\.\\\\|%2e%2e|%252e%252e|/etc/passwd|boot\\.ini|win\\.ini|\\{{\\{{|\\}}\\}}|%7b%7b|%7d%7d|\\$\\{{|__import__|config\\.|\\{{\\{{7\\*7\\}}\\}}|{union_select_regex}|{sql_tautology_regex}|{sql_comment_attack_regex}|information_schema|xp_cmdshell|sleep\\s*\\(|benchmark\\s*\\()'
                    THEN 1
                    ELSE 0
                END
            AS DOUBLE) AS has_clean_form_submission,
            CAST(
                CASE
                    WHEN request_lower RLIKE '{high_confidence_sql_regex}' THEN 3
                    WHEN request_lower RLIKE '{high_confidence_xss_regex}' THEN 3
                    WHEN request_lower RLIKE '{high_confidence_cmd_regex}' THEN 3
                    WHEN request_lower RLIKE '{high_confidence_traversal_regex}' THEN 3
                    WHEN request_lower RLIKE '{high_confidence_ssti_regex}' THEN 3
                    ELSE 0
                END
            AS DOUBLE) AS high_confidence_attack_score
        FROM __THIS__
        """
    )

    tokenizer = RegexTokenizer(
        inputCol="request_lower",
        outputCol="tokens",
        pattern=r"[^a-z0-9%._/\-]+",
        gaps=True,
        minTokenLength=2,
    )

    hashing_tf = HashingTF(
        inputCol="tokens",
        outputCol="tf_features",
        numFeatures=args.num_features,
        binary=True,
    )

    idf = IDF(inputCol="tf_features", outputCol="text_features")

    assembler = VectorAssembler(
        inputCols=feature_columns + ["text_features"],
        outputCol="features",
        handleInvalid="keep",
    )

    classifier = LogisticRegression(
        labelCol="label",
        featuresCol="features",
        predictionCol="prediction",
        probabilityCol="probability",
        rawPredictionCol="rawPrediction",
        weightCol="class_weight",
        maxIter=args.max_iter,
        regParam=0.015,
        elasticNetParam=0.0,
    )

    return Pipeline(stages=[request_normalizer, feature_builder, tokenizer, hashing_tf, idf, assembler, classifier])


def evaluate_predictions(predictions: DataFrame) -> dict[str, object]:
    metrics = {
        "accuracy": MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="accuracy",
        ).evaluate(predictions),
        "weighted_precision": MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="weightedPrecision",
        ).evaluate(predictions),
        "weighted_recall": MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="weightedRecall",
        ).evaluate(predictions),
        "f1": MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="f1",
        ).evaluate(predictions),
        "area_under_roc": BinaryClassificationEvaluator(
            labelCol="label",
            rawPredictionCol="rawPrediction",
            metricName="areaUnderROC",
        ).evaluate(predictions),
        "area_under_pr": BinaryClassificationEvaluator(
            labelCol="label",
            rawPredictionCol="rawPrediction",
            metricName="areaUnderPR",
        ).evaluate(predictions),
    }

    confusion_rows = (
        predictions.groupBy("label", "prediction")
        .count()
        .orderBy("label", "prediction")
        .collect()
    )
    metrics["confusion_matrix"] = [
        {
            "label": int(row["label"]),
            "prediction": int(row["prediction"]),
            "count": int(row["count"]),
        }
        for row in confusion_rows
    ]

    confusion_lookup = {
        (entry["label"], entry["prediction"]): entry["count"]
        for entry in metrics["confusion_matrix"]
    }
    true_negative = int(confusion_lookup.get((0, 0), 0))
    false_positive = int(confusion_lookup.get((0, 1), 0))
    false_negative = int(confusion_lookup.get((1, 0), 0))
    true_positive = int(confusion_lookup.get((1, 1), 0))
    normal_total = max(true_negative + false_positive, 1)
    malicious_total = max(true_positive + false_negative, 1)

    metrics["false_positive_count"] = false_positive
    metrics["false_negative_count"] = false_negative
    metrics["false_positive_rate"] = float(false_positive / normal_total)
    metrics["false_negative_rate"] = float(false_negative / malicious_total)
    return metrics


def save_metrics(path: Path, payload: dict[str, object]) -> None:
    # Reports are saved outside the model folder so the model folder only contains the runnable Spark model.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_existing_metrics(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def load_baseline_metrics(metrics_path: Path, comparison_path: Path) -> dict[str, object] | None:
    comparison_payload = load_existing_metrics(comparison_path)
    if comparison_payload is not None and comparison_payload.get("before") is not None:
        return comparison_payload["before"]
    return load_existing_metrics(metrics_path)


def add_class_weights(df: DataFrame) -> tuple[DataFrame, dict[int, float]]:
    counts = {
        int(row["label"]): int(row["count"])
        for row in df.groupBy("label").count().collect()
    }
    total = sum(counts.values())
    weights = {
        label: float(total / (len(counts) * count))
        for label, count in counts.items()
        if count > 0
    }

    weighted_df = df.withColumn(
        "class_weight",
        F.when(F.col("label") == 0, F.lit(weights.get(0, 1.0))).otherwise(F.lit(weights.get(1, 1.0))),
    )
    return weighted_df, weights


def build_benign_param_count(request_body: F.Column, request_text: F.Column) -> F.Column:
    # This counts how many normal form field names are present in the request.
    benign_param_count = F.lit(0)
    for param_name in BENIGN_PARAM_NAMES:
        body_match = request_body.rlike(fr"(^|&){param_name}=")
        query_match = request_text.rlike(fr"[?&]{param_name}=")
        benign_param_count = benign_param_count + F.when(body_match | query_match, F.lit(1)).otherwise(F.lit(0))
    return benign_param_count


def add_rule_based_signals(predictions: DataFrame) -> DataFrame:
    request_text = F.lower(F.col("request"))
    request_body = F.lower(F.regexp_extract("request", r"(?s)\n\n(.*)$", 1))
    request_path = F.lower(F.regexp_extract("request", r"^[A-Z]+\s+([^?\s]+)", 1))
    form_pair_count = F.when(F.length(request_body) > 0, F.size(F.split(request_body, "&"))).otherwise(F.lit(0))
    body_alphanumeric_count = F.length(F.regexp_replace(request_body, r"[^a-z0-9]", ""))
    body_symbol_count = F.length(F.regexp_replace(request_body, r"[a-z0-9]", ""))
    benign_param_count = build_benign_param_count(request_body, request_text)
    clean_form_shape = request_body.rlike(STRICT_SAFE_FORM_BODY_REGEX)
    body_alphanumeric_ratio = F.when(
        F.length(request_body) > 0,
        body_alphanumeric_count.cast("double") / F.greatest(body_symbol_count.cast("double"), F.lit(1.0)),
    ).otherwise(F.lit(0.0))

    obvious_sql = request_text.rlike(HIGH_CONFIDENCE_SQL_REGEX)
    obvious_sql_tautology = request_text.rlike(SQL_TAUTOLOGY_REGEX)
    obvious_union_select = request_text.rlike(UNION_SELECT_REGEX)
    obvious_sql_comment = request_text.rlike(SQL_COMMENT_ATTACK_REGEX)
    obvious_xss = request_text.rlike(HIGH_CONFIDENCE_XSS_REGEX)
    obvious_cmd = request_text.rlike(HIGH_CONFIDENCE_CMD_REGEX)
    obvious_traversal = request_text.rlike(HIGH_CONFIDENCE_TRAVERSAL_REGEX)
    obvious_ssti = request_text.rlike(HIGH_CONFIDENCE_SSTI_REGEX)
    attack_indicator = obvious_sql | obvious_sql_tautology | obvious_union_select | obvious_sql_comment | obvious_xss | obvious_cmd | obvious_traversal | obvious_ssti
    suspicious_safe_override_terms = request_text.rlike(
        r"(?i)(select|substring\s*\(|ascii\s*\(|information_schema|from\s+users|sleep\s*\(|benchmark\s*\(|xp_cmdshell|drop\s+table|windows[/\\]system32|/etc/passwd|\.\./|\.\.\\)"
    )

    # These safe patterns only apply to clean forms and safe GET patterns with no attack indicators.
    safe_search = request_text.rlike(SAFE_SEARCH_REGEX) & ~attack_indicator
    safe_api = request_text.rlike(SAFE_API_REGEX) & ~attack_indicator
    safe_smartevent_get = (
        request_text.rlike(r"(?i)^get\s+/(events|home|bookings|members|reviews|inquiries)(/[a-z0-9/_-]+)?(\?[a-z0-9_=&%+\-./]*)?\s+http/1\.1$")
        & ~attack_indicator
        & ~suspicious_safe_override_terms
    )
    safe_form_guard = (
        request_path.rlike(SAFE_FORM_ENDPOINT_REGEX)
        & clean_form_shape
        & (form_pair_count >= F.lit(1))
        & (form_pair_count <= F.lit(8))
        & (benign_param_count >= F.lit(2))
        & (body_alphanumeric_ratio >= F.lit(2.0))
        & ~attack_indicator
        & ~suspicious_safe_override_terms
    )
    safe_login_form = safe_form_guard & request_path.rlike(r"(?i)^/login(?:$|/)") & request_body.rlike(r"(^|&)username=") & request_body.rlike(r"(^|&)password=")
    safe_register_form = safe_form_guard & request_path.rlike(r"(?i)^/register(?:$|/)") & request_body.rlike(r"(^|&)email=") & request_body.rlike(r"(^|&)(username|password|name)=")
    safe_contact_form = safe_form_guard & request_path.rlike(r"(?i)^/contact(?:$|/)") & request_body.rlike(r"(^|&)name=") & request_body.rlike(r"(^|&)message=")
    safe_checkout_form = safe_form_guard & request_path.rlike(r"(?i)^/checkout(?:$|/)") & request_body.rlike(r"(^|&)(product_id|item|id)=") & request_body.rlike(r"(^|&)(quantity|qty)=")
    safe_profile_form = safe_form_guard & request_path.rlike(r"(?i)^/profile(?:$|/)") & request_body.rlike(r"(^|&)(name|email|phone|address|city)=")
    safe_support_form = safe_form_guard & request_path.rlike(r"(?i)^/support(?:$|/)") & request_body.rlike(r"(^|&)(name|email|message)=")
    safe_smartevent_form = safe_form_guard & request_path.rlike(
        r"(?i)^/(account/login|bookings/selectseats|bookings/payment|bookings/create|inquiries/create|reviews/create|members/create|events/create|events/edit)(?:$|/)"
    )
    safe_form_override = safe_login_form | safe_register_form | safe_contact_form | safe_checkout_form | safe_profile_form | safe_support_form | safe_smartevent_form

    with_reasons = predictions.withColumn(
        "rule_reason",
        F.when(obvious_sql | obvious_sql_tautology | obvious_union_select | obvious_sql_comment, F.lit("obvious_sql_injection"))
        .when(obvious_xss, F.lit("obvious_xss"))
        .when(obvious_cmd, F.lit("obvious_command_injection"))
        .when(obvious_traversal, F.lit("obvious_path_traversal"))
        .when(obvious_ssti, F.lit("obvious_ssti"))
        .when(safe_search, F.lit("safe_search_pattern"))
        .when(safe_api, F.lit("safe_api_pattern"))
        .when(safe_login_form, F.lit("safe_login_form"))
        .when(safe_register_form, F.lit("safe_register_form"))
        .when(safe_contact_form, F.lit("safe_contact_form"))
        .when(safe_checkout_form, F.lit("safe_checkout_form"))
        .when(safe_profile_form, F.lit("safe_profile_form"))
        .when(safe_support_form, F.lit("safe_support_form"))
        .when(safe_smartevent_form, F.lit("safe_smartevent_form"))
        .when(safe_smartevent_get, F.lit("safe_smartevent_get"))
        .otherwise(F.lit("model_only")),
    ).withColumn(
        "rule_based_malicious",
        F.when(attack_indicator, F.lit(1)).otherwise(F.lit(0)),
    ).withColumn(
        "rule_based_safe",
        F.when(safe_search | safe_api | safe_smartevent_get | safe_form_override, F.lit(1)).otherwise(F.lit(0)),
    )

    return with_reasons


def apply_prediction_threshold(predictions: DataFrame, threshold: float) -> DataFrame:
    threshold_literal = F.lit(float(threshold))
    with_probability = predictions.withColumn("probability_malicious", vector_to_array("probability")[1])
    with_rules = add_rule_based_signals(with_probability)

    # Safe overrides only turn requests normal after strict clean-form checks with no attack indicators.
    return with_rules.withColumn(
        "prediction",
        F.when(F.col("rule_based_malicious") == 1, F.lit(1.0))
        .when(F.col("rule_based_safe") == 1, F.lit(0.0))
        .when(F.col("probability_malicious") >= threshold_literal, F.lit(1.0))
        .otherwise(F.lit(0.0)),
    )


def build_metric_comparison(before_metrics: dict[str, object] | None, after_metrics: dict[str, object]) -> dict[str, object]:
    def resolve_metric(metrics_payload: dict[str, object], metric_name: str) -> float:
        if metric_name in metrics_payload:
            return float(metrics_payload[metric_name])

        confusion_rows = metrics_payload.get("confusion_matrix")
        if not isinstance(confusion_rows, list):
            return 0.0

        confusion_lookup = {
            (int(entry.get("label", 0)), int(entry.get("prediction", 0))): int(entry.get("count", 0))
            for entry in confusion_rows
            if isinstance(entry, dict)
        }
        true_negative = confusion_lookup.get((0, 0), 0)
        false_positive = confusion_lookup.get((0, 1), 0)
        false_negative = confusion_lookup.get((1, 0), 0)
        true_positive = confusion_lookup.get((1, 1), 0)

        if metric_name == "false_positive_count":
            return float(false_positive)
        if metric_name == "false_negative_count":
            return float(false_negative)
        if metric_name == "false_positive_rate":
            return float(false_positive / max(true_negative + false_positive, 1))
        if metric_name == "false_negative_rate":
            return float(false_negative / max(true_positive + false_negative, 1))
        return 0.0

    tracked_metrics = [
        "accuracy",
        "weighted_precision",
        "weighted_recall",
        "f1",
        "area_under_roc",
        "area_under_pr",
        "false_positive_count",
        "false_negative_count",
        "false_positive_rate",
        "false_negative_rate",
    ]
    comparison = {"before": before_metrics, "after": after_metrics}
    if before_metrics is not None:
        comparison["delta"] = {
            metric_name: resolve_metric(after_metrics, metric_name) - resolve_metric(before_metrics, metric_name)
            for metric_name in tracked_metrics
        }
    return comparison


def main() -> None:
    args = parse_args()
    project_root = args.project_root.resolve()
    data_path = project_root / "data_processed" / args.input_name
    model_dir = project_root / "model" / args.model_name
    report_dir = project_root / "reports" / "evaluation"
    spark_report_dir = report_dir / "spark_outputs"
    metrics_path = report_dir / f"{args.model_name}_metrics.json"
    comparison_path = report_dir / f"{args.model_name}_metrics_comparison.json"
    predictions_sample_dir = spark_report_dir / f"{args.model_name}_predictions_sample"

    spark = SparkSession.builder.appName("TrainWAFPipeline").master("local[*]").getOrCreate()
    spark.sparkContext.setLogLevel("WARN")

    before_metrics = load_baseline_metrics(metrics_path, comparison_path)

    base_df = (
        spark.read.parquet(str(data_path))
        .select("request", "label", "source", "attack_type")
        .dropna(subset=["request", "label"])
        .dropDuplicates(["request", "label"])
    )

    df, class_weights = add_class_weights(base_df)
    training_df, test_df = df.randomSplit([0.8, 0.2], seed=args.seed)

    feature_columns = [
        "request_length",
        "suspicious_char_count",
        "equals_count",
        "ampersand_count",
        "percent_count",
        "is_post",
        "is_get",
        "has_query_string",
        "has_body",
        "has_url_encoding",
        "has_sql_pattern",
        "has_xss_pattern",
        "has_command_pattern",
        "has_traversal_pattern",
        "has_ssti_pattern",
        "has_high_confidence_sql",
        "has_sql_tautology",
        "has_union_select_pattern",
        "has_sql_comment_attack",
        "has_high_confidence_xss",
        "has_high_confidence_command",
        "has_high_confidence_traversal",
        "has_high_confidence_ssti",
        "has_navigation_path",
        "has_simple_numeric_id",
        "has_login_fields",
        "has_benign_form_endpoint",
        "has_simple_benign_shape",
        "has_static_asset_path",
        "has_simple_form_body",
        "has_safe_search_request",
        "has_safe_api_request",
        "has_checkout_fields",
        "has_register_fields",
        "has_contact_fields",
        "has_profile_fields",
        "has_support_fields",
        "body_length",
        "form_key_value_pair_count",
        "benign_param_name_count",
        "has_common_benign_param",
        "body_alphanumeric_count",
        "body_symbol_count",
        "body_alphanumeric_to_symbol_ratio",
        "has_form_urlencoded_shape",
        "has_strict_safe_form_body",
        "has_balanced_form_pairs",
        "has_small_form_payload",
        "has_message_style_fields",
        "has_profile_style_fields",
        "has_clean_form_submission",
        "high_confidence_attack_score",
    ]

    pipeline = build_feature_pipeline(feature_columns, args)
    pipeline_model = pipeline.fit(training_df)
    raw_predictions = pipeline_model.transform(test_df)
    predictions = apply_prediction_threshold(raw_predictions, args.prediction_threshold).cache()

    metrics = evaluate_predictions(predictions)
    metrics["train_rows"] = int(training_df.count())
    metrics["test_rows"] = int(test_df.count())
    metrics["feature_columns"] = feature_columns
    metrics["model_name"] = args.model_name
    metrics["dataset_path"] = str(data_path)
    metrics["class_weights"] = class_weights
    metrics["prediction_threshold"] = float(args.prediction_threshold)
    metrics["training_label_distribution"] = {
        int(row["label"]): int(row["count"])
        for row in training_df.groupBy("label").count().collect()
    }
    metrics["full_label_distribution"] = {
        int(row["label"]): int(row["count"])
        for row in df.groupBy("label").count().collect()
    }
    metrics["imbalance_ratio_malicious_to_normal"] = float(
        metrics["full_label_distribution"].get(1, 0) / max(metrics["full_label_distribution"].get(0, 1), 1)
    )

    pipeline_model.write().overwrite().save(str(model_dir))
    save_metrics(metrics_path, metrics)
    save_metrics(comparison_path, build_metric_comparison(before_metrics, metrics))

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
        .limit(200)
        .write.mode("overwrite")
        .option("header", True)
        .csv(str(predictions_sample_dir))
    )

    print("\nTraining complete")
    print("-----------------")
    print(f"Train rows: {metrics['train_rows']}")
    print(f"Test rows: {metrics['test_rows']}")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Weighted precision: {metrics['weighted_precision']:.4f}")
    print(f"Weighted recall: {metrics['weighted_recall']:.4f}")
    print(f"F1 score: {metrics['f1']:.4f}")
    print(f"Area under ROC: {metrics['area_under_roc']:.4f}")
    print(f"Area under PR: {metrics['area_under_pr']:.4f}")
    print(f"False positive count: {metrics['false_positive_count']}")
    print(f"False negative count: {metrics['false_negative_count']}")
    print(f"Prediction threshold: {metrics['prediction_threshold']:.2f}")
    if before_metrics is not None:
        comparison = build_metric_comparison(before_metrics, metrics)
        false_positive_delta = comparison["delta"]["false_positive_count"]
        if false_positive_delta < 0:
            print(f"False positives improved by {-int(false_positive_delta)} compared with the previous baseline.")
        elif false_positive_delta > 0:
            print(f"False positives increased by {int(false_positive_delta)} compared with the previous baseline.")
        else:
            print("False positive count stayed the same as the previous baseline.")
    print(f"Saved model to: {model_dir}")
    print(f"Saved metrics to: {metrics_path}")
    print(f"Saved before-vs-after comparison to: {comparison_path}")
    print(f"Saved prediction sample to: {predictions_sample_dir}")

    predictions.unpersist()
    spark.stop()


if __name__ == "__main__":
    main()
