import streamlit as st
import requests

API_URL = "http://65.2.132.238:8000" 
st.set_page_config(page_title="Network Intrusion Detection", page_icon="🔐")
st.title("🔐 Network Intrusion Detection System")
st.write("Enter network traffic details to detect potential attacks")

st.subheader("Enter Network Traffic Features")

resp_p = st.number_input("Destination Port (id.resp_p)", min_value=0, max_value=65535, value=80)
bwd_payload_avg = st.number_input("Avg Backward Payload Size (bwd_pkts_payload.avg)", min_value=0.0, value=0.0)
psh_flag = st.number_input("PSH Flag Count (fwd_PSH_flag_count)", min_value=0, max_value=100, value=0)
urg_flag = st.number_input("URG Flag Count (fwd_URG_flag_count)", min_value=0, max_value=100, value=0)
last_window = st.number_input("Last Window Size (fwd_last_window_size)", min_value=0, max_value=65535, value=64)

if st.button("🔍 Detect Attack"):
    payload = {
        "resp_p": resp_p,
        "bwd_payload_avg": bwd_payload_avg,
        "psh_flag": psh_flag,
        "urg_flag": urg_flag,
        "last_window": last_window
    }

    with st.spinner("Analyzing traffic..."):
        try:
            response = requests.post(f"{API_URL}/predict", json=payload, timeout=10)
            response.raise_for_status()
            result = response.json()

            attack_name = result["attack_name"]
            is_safe = result["is_safe"]

            if is_safe:
                st.success(f"✅ SAFE — Normal Traffic Detected: {attack_name}")
            else:
                st.error(f"🚨 ALERT — Attack Detected: {attack_name}")

        except requests.exceptions.RequestException as e:
            st.error(f"Could not reach the backend API: {e}")