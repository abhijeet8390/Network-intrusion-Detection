import streamlit as st
import requests

API_URL = "http://65.2.132.238:8000/predict"

st.title("🔐 Network Intrusion Detection System")
st.markdown("Enter network traffic details below:")

# Input fields
resp_p = st.number_input("Destination Port (id.resp_p)", min_value=0, max_value=65535, value=80)
bwd_payload_avg = st.number_input("Avg Backward Payload Size (bwd_pkts_payload.avg)", min_value=0.0, value=0.0)
psh_flag = st.number_input("PSH Flag Count (fwd_PSH_flag_count)", min_value=0, max_value=100, value=0)
urg_flag = st.number_input("URG Flag Count (fwd_URG_flag_count)", min_value=0, max_value=100, value=0)
last_window = st.number_input("Last Window Size (fwd_last_window_size)", min_value=0, max_value=65535, value=64)

if st.button("🔍 Detect Attack"):
    input_data = {
        "resp_p": resp_p,
        "bwd_payload_avg": bwd_payload_avg,
        "psh_flag": psh_flag,
        "urg_flag": urg_flag,
        "last_window": last_window
    }

    try:
        response = requests.post(API_URL, json=input_data)
        result = response.json()

        if response.status_code == 200:
            attack_name = result["attack_name"]
            is_safe = result["is_safe"]

            if is_safe:
                st.success(f"✅ SAFE — Normal Traffic Detected: **{attack_name}**")
            else:
                st.error(f"🚨 ALERT — Attack Detected: **{attack_name}**")
        else:
            st.error(f"API Error: {response.status_code}")
            st.write(result)

    except requests.exceptions.ConnectionError:
        st.error("❌ Could not connect to the FastAPI server. Make sure it's running.")