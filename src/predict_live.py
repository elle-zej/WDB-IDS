import joblib
import pandas as pd

# ADD YOUR PATH:

# MODEL_PATH    = "/model/path"
# ENCODER_PATH  = "/models/encoder"
# FEATURES_PATH = "/models/features"
# SCALER_PATH   = "/models/scaler"

model         = joblib.load(MODEL_PATH)
encoder       = joblib.load(ENCODER_PATH)
final_features = joblib.load(FEATURES_PATH)

cat_cols = ["state", "proto", "service"]

def predict_flow(flow_features: dict):
    """
    Takes a dict of computed flow features, aligns columns to the
    training feature order, encodes categoricals, and returns
    (label, attack_probability).
    """
    X_live = pd.DataFrame([flow_features])

    # Align to exact training feature order — missing cols filled with 0
    X_live = X_live.reindex(columns=final_features, fill_value=0)

    # Encode categorical columns using the same encoder fit on training data.
    # handle_unknown='use_encoded_value' means unseen categories (e.g. a
    # service the model never saw) get encoded as -1 rather than crashing.

    encoded = encoder.transform(X_live[cat_cols])
    for i, col in enumerate(cat_cols):
        X_live[col] = encoded[:, i]

    prediction  = model.predict(X_live)[0]
    probability = model.predict_proba(X_live)[0][1]

    label = "Attack" if prediction == 1 else "Normal"
    return label, probability