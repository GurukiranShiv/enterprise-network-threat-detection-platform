#!/usr/bin/env bash
set -e
python detection_engine/main.py --input data/sample --output data/alerts/alerts.json
streamlit run streamlit_app/app.py
