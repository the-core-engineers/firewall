#!/bin/bash
# Start core
cd core
pip install -r requirements.txt
python -m uvicorn main:app --reload &
CORE_PID=$!

# Start webui
cd ../webui
npm install
npm run dev &
WEBUI_PID=$!

wait
