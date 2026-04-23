from __future__ import annotations

import argparse
import json
import re
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

from pyspark.ml import PipelineModel
from pyspark.sql import SparkSession

from train_pipeline import (
    BENIGN_PARAM_NAMES,
    HIGH_CONFIDENCE_CMD_REGEX,
    HIGH_CONFIDENCE_SQL_REGEX,
    HIGH_CONFIDENCE_SSTI_REGEX,
    HIGH_CONFIDENCE_TRAVERSAL_REGEX,
    HIGH_CONFIDENCE_XSS_REGEX,
    SAFE_FORM_ENDPOINT_REGEX,
    SQL_COMMENT_ATTACK_REGEX,
    SQL_TAUTOLOGY_REGEX,
    STRICT_SAFE_FORM_BODY_REGEX,
    UNION_SELECT_REGEX,
    apply_prediction_threshold,
)


# These words make a GET request suspicious enough that it should not receive the fast safe allow.
# It will either be blocked by attack rules above or passed to the PySpark model fallback.
SAFE_GET_SUSPICIOUS_REGEX = (
    r"(?i)(?:select|substring\s*\(|ascii\s*\(|information_schema|from\s+users|"
    r"sleep\s*\(|benchmark\s*\(|xp_cmdshell|drop\s+table|"
    r"windows[/\\]system32|/etc/passwd|\.\./|\.\.\\)"
)


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]

    parser = argparse.ArgumentParser(
        description="Run a small local API around the saved PySpark WAF model."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host for the local WAF API.")
    parser.add_argument("--port", type=int, default=8765, help="Port for the local WAF API.")
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
        "--prediction-threshold",
        type=float,
        default=0.70,
        help="Probability threshold used when the rule-based checks do not decide.",
    )
    return parser.parse_args()


def build_request_text(payload: dict[str, Any]) -> str:
    def payload_value(*names: str, default: str = "") -> Any:
        for name in names:
            if name in payload and payload[name] is not None:
                return payload[name]
        return default

    # The API accepts a ready-made raw request, or normal web pieces from the MVC middleware.
    raw_request = str(payload_value("rawRequest", "RawRequest")).strip()
    if raw_request:
        return raw_request

    # Accept camelCase and PascalCase because C# and Python serializers may name fields differently.
    method = str(payload_value("method", "Method", default="GET")).upper().strip()
    path = str(payload_value("path", "Path", default="/")).strip() or "/"
    query_string = str(payload_value("queryString", "QueryString")).strip()
    body = str(payload_value("body", "Body")).strip()

    if query_string and not query_string.startswith("?"):
        query_string = f"?{query_string}"

    request_text = f"{method} {path}{query_string} HTTP/1.1"
    if body:
        request_text = f"{request_text}\n\n{body}"
    return request_text


def decode_for_rules(value: str) -> str:
    # Decode twice so encoded demo payloads such as %253Cscript%253E are still visible to the rules.
    decoded_once = unquote_plus(value)
    decoded_twice = unquote_plus(decoded_once)

    # Some browsers/editors turn normal SQL quotes into smart quotes, so normalise them for rules.
    return (
        decoded_twice.replace("\u2018", "'")
        .replace("\u2019", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
    )


def parse_request_parts(request_text: str) -> tuple[str, str, str]:
    first_line = request_text.splitlines()[0] if request_text else ""
    first_line_parts = first_line.split()
    method = first_line_parts[0].upper() if len(first_line_parts) >= 1 else "GET"
    target = first_line_parts[1] if len(first_line_parts) >= 2 else "/"
    path = target.split("?", 1)[0]
    body = request_text.split("\n\n", 1)[1] if "\n\n" in request_text else ""
    return method, path, body


def make_rule_result(
    request_text: str,
    prediction: int,
    probability: float,
    rule_based_malicious: int,
    rule_based_safe: int,
    rule_reason: str,
    threshold: float,
) -> dict[str, Any]:
    return {
        "request": request_text,
        "prediction": prediction,
        "probability_malicious": probability,
        "rule_based_malicious": rule_based_malicious,
        "rule_based_safe": rule_based_safe,
        "rule_reason": rule_reason,
        "action": "block" if prediction == 1 else "allow",
        "threshold": float(threshold),
        "model_used": False,
    }


def fast_rule_decision(request_text: str, threshold: float) -> dict[str, Any] | None:
    # Fast rules keep the live website demo responsive for obvious attacks and obvious clean app traffic.
    decoded_request = decode_for_rules(request_text)
    rule_text = f"{request_text}\n{decoded_request}"
    method, path, body = parse_request_parts(request_text)
    decoded_body = decode_for_rules(body)

    attack_patterns = [
        ("obvious_sql_injection", HIGH_CONFIDENCE_SQL_REGEX),
        ("obvious_sql_injection", SQL_TAUTOLOGY_REGEX),
        ("obvious_sql_injection", UNION_SELECT_REGEX),
        ("obvious_sql_injection", SQL_COMMENT_ATTACK_REGEX),
        ("obvious_xss", HIGH_CONFIDENCE_XSS_REGEX),
        ("obvious_command_injection", HIGH_CONFIDENCE_CMD_REGEX),
        ("obvious_path_traversal", HIGH_CONFIDENCE_TRAVERSAL_REGEX),
        ("obvious_ssti", HIGH_CONFIDENCE_SSTI_REGEX),
    ]

    for reason, pattern in attack_patterns:
        if re.search(pattern, rule_text):
            return make_rule_result(request_text, 1, 1.0, 1, 0, reason, threshold)

    if (
        method == "GET"
        and re.search(
            r"(?i)^get\s+/[a-z0-9/_\-.]*(\?[a-z0-9_=&%+\-./]*)?\s+http/1\.1$",
            request_text,
        )
        and not re.search(SAFE_GET_SUSPICIOUS_REGEX, decoded_request)
    ):
        return make_rule_result(request_text, 0, 0.0, 0, 1, "safe_clean_get", threshold)

    if method == "POST" and re.search(SAFE_FORM_ENDPOINT_REGEX, path):
        form_pairs = [pair for pair in body.split("&") if "=" in pair]
        form_keys = {decode_for_rules(pair.split("=", 1)[0]).lower() for pair in form_pairs}
        benign_key_count = sum(1 for key in form_keys if key in BENIGN_PARAM_NAMES)
        clean_encoded_body = re.search(STRICT_SAFE_FORM_BODY_REGEX, body) is not None
        clean_decoded_body = re.search(r"(?i)^[a-z0-9_]+=[a-z0-9@._+\-,/ ]+(&[a-z0-9_]+=[a-z0-9@._+\-,/ ]+)*$", decoded_body) is not None

        if (
            1 <= len(form_pairs) <= 8
            and benign_key_count >= 1
            and (clean_encoded_body or clean_decoded_body)
            and not re.search(SAFE_GET_SUSPICIOUS_REGEX, decoded_request)
        ):
            return make_rule_result(request_text, 0, 0.0, 0, 1, "safe_smartevent_form", threshold)

    return None


def print_result(result: dict[str, Any], request_text: str) -> None:
    first_line = request_text.splitlines()[0] if request_text else "<empty request>"
    print(
        f"[WAF] {result['action'].upper()} | probability={result['probability_malicious']:.4f} "
        f"| reason={result['rule_reason']} | {first_line}",
        flush=True,
    )


class WafRuntime:
    def __init__(self, project_root: Path, model_name: str, threshold: float) -> None:
        self.project_root = project_root.resolve()
        self.model_path = self.project_root / "model" / model_name
        self.staging_dir = self.project_root / "demo_files" / "_waf_api_staging"
        self.threshold = threshold
        self.spark = None
        self.model = None

        # The live demo should start quickly, so Spark is loaded only when the ML fallback is needed.
        # Obvious attacks and obvious clean website requests are handled by fast rules first.

    def ensure_model_loaded(self) -> None:
        if self.spark is not None and self.model is not None:
            return

        print("Loading Spark model for ML fallback...", flush=True)
        self.spark = (
            SparkSession.builder.appName("WAFPredictionAPI")
            .master("local[*]")
            .config("spark.sql.codegen.wholeStage", "false")
            .getOrCreate()
        )
        self.spark.sparkContext.setLogLevel("WARN")
        self.model = PipelineModel.load(str(self.model_path))
        print("Spark model loaded.", flush=True)

    def predict(self, request_text: str, threshold: float | None = None) -> dict[str, Any]:
        active_threshold = self.threshold if threshold is None else threshold

        fast_result = fast_rule_decision(request_text, active_threshold)
        if fast_result is not None:
            print_result(fast_result, request_text)
            return fast_result

        self.ensure_model_loaded()
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        staging_path = self.staging_dir / f"request_{uuid.uuid4().hex}.jsonl"

        try:
            # Reading JSONL matches the existing batch prediction script and avoids unstable Python-worker creation.
            staging_path.write_text(json.dumps({"request": request_text}) + "\n", encoding="utf-8")
            assert self.spark is not None
            assert self.model is not None
            request_df = self.spark.read.json(str(staging_path))
            raw_predictions = self.model.transform(request_df)
            predictions = apply_prediction_threshold(raw_predictions, active_threshold)
            row = predictions.select(
                "request",
                "prediction",
                "probability_malicious",
                "rule_based_malicious",
                "rule_based_safe",
                "rule_reason",
            ).first()
        finally:
            staging_path.unlink(missing_ok=True)

        prediction = int(row["prediction"])
        result = {
            "request": row["request"],
            "prediction": prediction,
            "probability_malicious": float(row["probability_malicious"]),
            "rule_based_malicious": int(row["rule_based_malicious"]),
            "rule_based_safe": int(row["rule_based_safe"]),
            "rule_reason": row["rule_reason"],
            "action": "block" if prediction == 1 else "allow",
            "threshold": float(active_threshold),
            "model_used": True,
        }
        print_result(result, request_text)
        return result


class WafRequestHandler(BaseHTTPRequestHandler):
    runtime: WafRuntime

    def send_json(self, status_code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_json(200, {"status": "ok"})

    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_json(
                200,
                {
                    "status": "ready",
                    "model_path": str(self.runtime.model_path),
                    "model_loaded": self.runtime.model is not None,
                },
            )
            return
        self.send_json(404, {"error": "Use POST /check or GET /health."})

    def do_POST(self) -> None:
        if self.path != "/check":
            self.send_json(404, {"error": "Use POST /check."})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            payload_bytes = self.rfile.read(content_length)
            payload = json.loads(payload_bytes.decode("utf-8")) if payload_bytes else {}
            request_text = build_request_text(payload)
            threshold_value = payload.get("threshold", payload.get("Threshold"))
            threshold = float(threshold_value) if threshold_value is not None else None
            result = self.runtime.predict(request_text, threshold)
            self.send_json(200, result)
        except Exception as exc:
            self.send_json(500, {"error": str(exc)})

    def log_message(self, format: str, *args: Any) -> None:
        # Keep the API terminal readable during the live demo.
        return


def main() -> None:
    args = parse_args()
    runtime = WafRuntime(args.project_root, args.model_name, args.prediction_threshold)
    WafRequestHandler.runtime = runtime

    server = ThreadingHTTPServer((args.host, args.port), WafRequestHandler)
    print("WAF API ready")
    print("-------------")
    print(f"Health check: http://{args.host}:{args.port}/health")
    print(f"Prediction endpoint: http://{args.host}:{args.port}/check")
    print(f"Model path: {runtime.model_path}")
    print("Spark model loading: lazy, only when ML fallback is needed")
    print(f"Prediction threshold: {args.prediction_threshold:.2f}")
    server.serve_forever()


if __name__ == "__main__":
    main()
