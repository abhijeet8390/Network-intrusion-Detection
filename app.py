import streamlit as st
import pickle
import numpy as np
import pandas as pd

with open("rf_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("le_proto.pkl", "rb") as f:
    le_proto = pickle.load(f)

with open("le_service.pkl", "rb") as f:
    le_service = pickle.load(f)

with open("le_target.pkl", "rb") as f:
    le_target = pickle.load(f)
    
# Page title
st.title("🔐 Network Intrusion Detection System")
st.write("Enter network traffic details to detect potential attacks")

# Input fields for top 5 features
st.subheader("Enter Network Traffic Features")

resp_p = st.number_input("Destination Port (id.resp_p)", min_value=0, max_value=65535, value=80)

bwd_payload_avg = st.number_input("Avg Backward Payload Size (bwd_pkts_payload.avg)", min_value=0.0, value=0.0)

psh_flag = st.number_input("PSH Flag Count (fwd_PSH_flag_count)", min_value=0, max_value=100, value=0)

urg_flag = st.number_input("URG Flag Count (fwd_URG_flag_count)", min_value=0, max_value=100, value=0)

last_window = st.number_input("Last Window Size (fwd_last_window_size)", min_value=0, max_value=65535, value=64)

# Predict button
if st.button("🔍 Detect Attack"):
    
    # Prepare input data
    input_data = np.array([[resp_p, bwd_payload_avg, psh_flag, urg_flag, last_window]])
    
    # Make prediction
    prediction = model.predict(input_data)
    
    # Decode prediction back to attack name
    attack_name = le_target.inverse_transform(prediction)[0]
    
    # Show result
    if attack_name in ["MQTT_Publish", "Thing_Speak", "Wipro_bulb"]:
        st.success(f"✅ SAFE — Normal Traffic Detected: {attack_name}")
    else:
        st.error(f"🚨 ALERT — Attack Detected: {attack_name}")
        
