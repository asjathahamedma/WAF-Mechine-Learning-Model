# SmartEvent MVC + PySpark WAF Demo

This folder contains a copied version of the SmartEvent MVC website.
The original project at `C:\Users\Asjath\Desktop\SmartEventMVC` was not edited.

## What Was Added

- `src/waf_api.py` starts a small local API around the saved PySpark WAF model.
- The copied MVC website calls that API before MVC controllers run.
- If the WAF predicts malicious traffic, the MVC middleware returns a `403 Request blocked by WAF` page.
- If the request is clean, the MVC website continues normally.

## Run The Demo

Open two terminals.

Terminal 1: start the WAF API.

```powershell
cd C:\Users\Asjath\Desktop\Pyspark_WAF_Project
.\.venv\Scripts\python.exe .\src\waf_api.py
```

Wait until you see:

```text
WAF API ready
```

Terminal 2: start the copied MVC website.

```powershell
cd C:\Users\Asjath\Desktop\Pyspark_WAF_Project\demo_website\SmartEventMVC_WAF_Demo\SmartEventMVC
dotnet run
```

Open the website:

```text
http://localhost:5284
```

## Demo Requests

Clean request that should be allowed:

```text
http://localhost:5284/Events?searchString=music
```

XSS request that should be blocked:

```text
http://localhost:5284/Events?searchString=<script>alert(1)</script>
```

SQL injection request that should be blocked:

```text
http://localhost:5284/Events?searchString=' OR '1'='1
```

Clean login form should be allowed:

```text
mobile=0712345678
password=123
```

Malicious login payload should be blocked:

```text
mobile=0712345678
password=' OR '1'='1
```

## Important Notes

- Start the WAF API before the website for the best live demo.
- The MVC app is configured with `FailOpen: true`, so the website still works if the WAF API is not running.
- For the demo, say the WAF is a hybrid system: PySpark ML model plus rule-based security overrides.
- Do not claim 100% accuracy. Say it improves practical detection and reduces false positives for clean SmartEvent forms.
