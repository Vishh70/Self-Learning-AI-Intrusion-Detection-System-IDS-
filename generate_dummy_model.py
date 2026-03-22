import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

# Create dummy training data with 16 features (Phase 9/11 Architecture)
# Order: src_ip_numeric, dst_ip_numeric, protocol_number, packet_length, ttl, 
#        src_port, dst_port, is_tcp, is_udp, is_icmp, src_is_private, 
#        dst_is_private, has_payload, burstiness, conn_count, avg_packet_length
X_dummy = np.array([
    [167772160, 167772161, 6, 64, 64, 443, 50000, 1, 0, 0, 1, 1, 1, 1, 1, 64.0],
    [167772160, 167772161, 6, 128, 64, 80, 50001, 1, 0, 0, 1, 1, 1, 2, 2, 96.0],
    [167772160, 167772162, 17, 256, 128, 53, 50002, 0, 1, 0, 1, 1, 1, 1, 1, 256.0],
    [3232235521, 3232235522, 1, 32, 255, 0, 0, 0, 0, 1, 1, 1, 0, 5, 5, 40.0]
])

# Train a basic Isolation Forest model
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
model.fit(X_dummy)

# Add dummy calibration stats to support Phase 11 Risk % scaling
model.calibration_stats_ = {
    "min": -0.8,
    "p01": -0.75,
    "p05": -0.7,
    "p10": -0.65,
    "p25": -0.6,
    "p50": -0.55,
    "max": -0.1,
    "threshold": -0.5
}

# Save the model
joblib.dump(model, "saved_model.pkl")
print("Successfully generated UPGRADED saved_model.pkl (16 features)!")
