# ==========================================
# IOT SENTINEL IDS - API BACKEND
# ==========================================
import pandas as pd
import numpy as np
import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

# --- 1. API Metadata & Configuration (UI Süslemeleri) ---
tags_metadata = [
    {
        "name": "🔍 Detection Engine",
        "description": "The AI brain of the system. Analyzes network flow features to detect attacks.",
    },
    {
        "name": "🗄️ Security Logs",
        "description": "Manage the intrusion database. View, add, or delete security events.",
    },
]

app = FastAPI(
    title="🛡️ IoT Sentinel IDS API",
    description="""
    This API serves as the backend for the **Real-Time Intrusion Detection System** developed for the Advanced Programming course.
    
    ## 🚀 Key Features
    * **Real-time Prediction**: Uses a Random Forest model to classify traffic.
    * **Firewall Simulation**: Automatically generates `BLOCK` rules for threats.
    * **Forensics**: detailed logging of every analyzed packet.
    
    ## 👤 Developer
    **Furkan Kartal** - Computer Engineering, Haliç University.
    """,
    version="2.0.0",
    contact={
        "name": "Furkan Kartal",
        "email": "22092090040@ogr.halic.edu.tr",
    },
    openapi_tags=tags_metadata
)

# --- 2. Load Model & Encoder ---
print("Loading AI Models...")
try:
    model = joblib.load('iot_security_model.pkl')
    label_encoder = joblib.load('label_encoder.pkl')
    print("SUCCESS: Model and Encoder loaded.")
except Exception as e:
    print(f"CRITICAL ERROR: {e}")
    model = None
    label_encoder = None

# --- 3. Data Models ---
class NetworkFlow(BaseModel):
    features: List[float]  # Example: [0, 1, 0.5, 100, ...]

class SecurityLog(BaseModel):
    id: Optional[int] = None
    source_ip: str
    destination_ip: str
    protocol: str
    status: str

# --- 4. Fake Database ---
fake_database = [
    {"id": 1, "source_ip": "192.168.1.10", "destination_ip": "10.0.0.5", "protocol": "TCP", "status": "Normal"},
    {"id": 2, "source_ip": "172.16.0.5", "destination_ip": "10.0.0.5", "protocol": "UDP", "status": "Attack detected"}
]

# --- 5. ENDPOINTS ---

@app.get("/", include_in_schema=False)
def home():
    return {"message": "System is Online. Go to /docs for the UI."}

# --- PREDICTION ENGINE ---
@app.post("/predict", tags=["🔍 Detection Engine"])
def predict_attack(flow: NetworkFlow):
    """
    **Analyzes network traffic** features and predicts potential threats.
    
    - **Input**: List of numerical network features.
    - **Output**: Prediction (Normal/Attack) and Firewall Action.
    """
    if not model:
        raise HTTPException(status_code=500, detail="Model not loaded.")
    
    try:
        # Prepare data
        input_data = np.array(flow.features).reshape(1, -1)
        
        # Predict
        prediction_index = model.predict(input_data)[0]
        prediction_name = label_encoder.inverse_transform([prediction_index])[0]
        
        # Firewall Logic
        normal_labels = ['MQTT_Publish', 'Thing_Speak', 'Wipro_bulb', 'Normal']
        
        if prediction_name in normal_labels:
            action = "ALLOW"
            risk = "LOW"
            msg = "Traffic is safe."
        else:
            action = "BLOCK_IP_IMMEDIATELY"
            risk = "CRITICAL"
            msg = f"Threat Detected: {prediction_name}"

        return {
            "prediction": prediction_name,
            "action": action,
            "risk_level": risk,
            "system_message": msg
        }

    except Exception as e:
        return {"error": str(e)}

# --- LOG MANAGEMENT (CRUD) ---
@app.get("/logs", tags=["🗄️ Security Logs"], response_model=List[SecurityLog])
def get_logs():
    """Retrieve all security logs from the database."""
    return fake_database

@app.get("/logs/{log_id}", tags=["🗄️ Security Logs"])
def get_log_by_id(log_id: int):
    """Find a specific log by its ID."""
    for log in fake_database:
        if log["id"] == log_id:
            return log
    raise HTTPException(status_code=404, detail="Log not found")

@app.post("/logs", tags=["🗄️ Security Logs"])
def add_log(log: SecurityLog):
    """Manually add a new security event log."""
    new_id = len(fake_database) + 1
    log.id = new_id
    fake_database.append(log.dict())
    return {"message": "Log added", "log": log}

@app.put("/logs/{log_id}", tags=["🗄️ Security Logs"])
def update_log(log_id: int, updated_log: SecurityLog):
    """Update an existing log entry."""
    for i, log in enumerate(fake_database):
        if log["id"] == log_id:
            updated_log.id = log_id
            fake_database[i] = updated_log.dict()
            return {"message": "Log updated", "log": updated_log}
    raise HTTPException(status_code=404, detail="Log not found")

@app.delete("/logs/{log_id}", tags=["🗄️ Security Logs"])
def delete_log(log_id: int):
    """Remove a log entry permanently."""
    for i, log in enumerate(fake_database):
        if log["id"] == log_id:
            del fake_database[i]
            return {"message": "Log deleted"}
    raise HTTPException(status_code=404, detail="Log not found")