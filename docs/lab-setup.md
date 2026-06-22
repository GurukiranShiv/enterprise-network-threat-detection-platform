# Lab Setup

## Minimum Setup

- Windows laptop
- VS Code
- Python 3.10+
- Docker Desktop, optional for Elastic/Kibana

## Basic Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python detection_engine/main.py --input data/sample --output data/alerts/alerts.json
streamlit run streamlit_app/app.py
```

## Elastic/Kibana Run

```bash
docker compose up -d elasticsearch kibana
python detection_engine/main.py --input data/sample --output data/alerts/alerts.json --send-elastic
```

Open Kibana at:

```text
http://localhost:5601
```

Create a data view:

```text
network-threat-alerts-*
```
