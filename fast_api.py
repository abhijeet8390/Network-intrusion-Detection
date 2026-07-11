import pickle
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Network Intrusion Detection System")

# Load model and encoders once at startup
with open("rf_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("le_proto.pkl", "rb") as f:
    le_proto = pickle.load(f)

with open("le_service.pkl", "rb") as f:
    le_service = pickle.load(f)

with open("le_target.pkl", "rb") as f:
    le_target = pickle.load(f)


class TrafficInput(BaseModel):
    resp_p: int
    bwd_payload_avg: float
    psh_flag: int
    urg_flag: int
    last_window: int


class PredictionResponse(BaseModel):
    attack_name: str
    is_safe: bool


SAFE_LABELS = ["MQTT_Publish", "Thing_Speak", "Wipro_bulb"]


@app.post("/predict", response_model=PredictionResponse)
def predict(data: TrafficInput):
    input_data = np.array([[
        data.resp_p,
        data.bwd_payload_avg,
        data.psh_flag,
        data.urg_flag,
        data.last_window
    ]])

    prediction = model.predict(input_data)
    attack_name = le_target.inverse_transform(prediction)[0]
    is_safe = attack_name in SAFE_LABELS

    return PredictionResponse(attack_name=attack_name, is_safe=is_safe)


@app.get("/health")
def health():
    return {"status": "ok"}