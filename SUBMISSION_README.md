# PySpark WAF Project - Submission Run Guide

## 1. Project Overview

This project is a Web Application Firewall prototype that detects malicious HTTP requests using a PySpark machine learning pipeline and rule-based security checks.

The system can detect common web attacks such as:

- SQL Injection
- Cross-Site Scripting
- Command Injection
- Path Traversal
- Server-Side Template Injection
- Suspicious encoded HTTP payloads

The project also includes an ASP.NET Core MVC ticket/event booking demo website. The website calls the Python WAF API before processing requests, so malicious requests can be blocked during the live demo.

## 2. Important Folders

- `src` - Python scripts for dataset building, model training, evaluation, prediction, and WAF API.
- `data_raw` - Original raw datasets.
- `data_processed` - Cleaned master dataset used by Spark.
- `model` - Final trained PySpark WAF model.
- `demo_website` - ASP.NET Core MVC website integrated with the WAF API.
- `demo_files` - Example logs and demo screenshots.
- `reports` - Final report and evaluation output.

## 3. Software Requirements

Install these before running the project:

- Python 3.11 or newer
- Java JDK 17 or newer
- .NET SDK matching the MVC project target framework
- PowerShell or VS Code terminal

## 4. Create Python Environment

Open PowerShell in the project folder:

```powershell
cd C:\Users\Asjath\Desktop\Pyspark_WAF_Project
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## 5. Rebuild Dataset, Train, and Evaluate

Run these commands in order if you want to rebuild the full pipeline:

```powershell
python .\src\build_master_dataset.py
python .\src\train_pipeline.py
python .\src\evaluate_pipeline.py
```

Expected evaluation result from the final trained model:

- Accuracy: about 98.34%
- False positives: low
- Attack detection: strong for obvious SQLi, XSS, command injection, traversal, and SSTI examples

Important: this project does not claim 100% accuracy. It is a practical prototype with measurable evaluation results.

## 6. Test Predictions on New Logs

Edit this file if you want to test new HTTP requests:

```text
demo_files\new_unseen_logs.log
```

Then run:

```powershell
python .\src\predict_unseen.py
```

The prediction output will be written into the demo output folder.

## 7. Run the Live WAF Demo

Use two PowerShell terminals.

Terminal 1 - start the Python WAF API:

```powershell
cd C:\Users\Asjath\Desktop\Pyspark_WAF_Project
.\.venv\Scripts\python.exe .\src\waf_api.py
```

Terminal 2 - start the ASP.NET Core MVC website:

```powershell
cd C:\Users\Asjath\Desktop\Pyspark_WAF_Project\demo_website\SmartEventMVC_WAF_Demo\SmartEventMVC
dotnet restore
dotnet run
```

Open the website in a browser. The demo website usually runs on:

```text
http://localhost:5284
```

## 8. Demo Test URLs

Normal request that should be allowed:

```text
http://localhost:5284/Events?searchString=music
```

XSS request that should be blocked:

```text
http://localhost:5284/Events?searchString=%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

SQL Injection request that should be blocked:

```text
http://localhost:5284/Events?searchString=%27%20OR%20%271%27%3D%271
```

Command Injection request that should be blocked:

```text
http://localhost:5284/Events?searchString=%3Bwhoami
```

Path Traversal request that should be blocked:

```text
http://localhost:5284/Events?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

## 9. What to Explain in the Viva

- The project solves the problem of detecting malicious web requests before they reach the application.
- PySpark was used to build a scalable data processing and machine learning pipeline.
- The system uses both machine learning and rule-based checks.
- Rule-based checks catch obvious attacks quickly.
- The ML model handles less obvious request patterns.
- Safe-form features were added to reduce false positives on normal POST forms such as login, contact, and checkout.
- The final system was integrated into a real MVC website to prove that it works in a live web application flow.

## 10. Submission Notes

The `.venv`, `bin`, `obj`, browser cache, and Python cache folders are not included in the submission because they are generated automatically and make the project very large.

To recreate the environment, use:

```powershell
pip install -r requirements.txt
```
