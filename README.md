# PySpark WAF Machine Learning Project

This project is a hybrid Web Application Firewall that detects malicious HTTP requests using a PySpark machine learning pipeline plus rule-based security checks.

## Main Capabilities

- Detects SQL Injection, Cross-Site Scripting, Command Injection, Path Traversal, SSTI, and suspicious encoded payloads
- Builds a master dataset from multiple HTTP request datasets
- Trains and evaluates a PySpark attack-classification pipeline
- Exposes a Python WAF API for real-time request inspection
- Integrates with an ASP.NET Core MVC ticket booking demo website

## Project Structure

- `src` - dataset building, training, evaluation, prediction, and WAF API scripts
- `data_raw` - original datasets
- `data_processed` - processed master dataset used by Spark
- `model` - final trained PySpark WAF model
- `demo_website` - ASP.NET Core MVC demo site integrated with the WAF API
- `demo_files` - sample unseen logs and demo assets
- `reports` - report material, charts, and presentation files

## Technologies Used

- Python
- PySpark
- scikit-learn style ML workflow inside Spark ML
- ASP.NET Core MVC
- PowerShell

## How To Run

1. Create and activate a virtual environment.
2. Install dependencies from `requirements.txt`.
3. Run `build_master_dataset.py`, `train_pipeline.py`, and `evaluate_pipeline.py` if you want to rebuild the model.
4. Start `src/waf_api.py`.
5. Start the MVC website in `demo_website/SmartEventMVC_WAF_Demo/SmartEventMVC`.

Detailed run instructions are available in [SUBMISSION_README.md](./SUBMISSION_README.md).

## Demo Highlights

- Obvious attacks are blocked quickly by fast WAF rules.
- Less-obvious suspicious requests can fall back to the PySpark model.
- The final system was demonstrated inside a working event booking website.

## Notes

- This project is a practical security prototype and does not claim 100% accuracy.
- Generated folders such as `.venv`, `bin`, and `obj` are intentionally excluded from version control.
