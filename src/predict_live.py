import joblib
import pandas as pd

MODEL_PATH = "/Users/jezelleoverstreet/WDB_IDS/models/xgb_model.pkl"   # or rf_model.pkl
ENCODER_PATH = "/Users/jezelleoverstreet/WDB_IDS/models/ordinal_encoder.pkl"
FEATURES_PATH = "/Users/jezelleoverstreet/WDB_IDS/models/final_features.pkl"

model = joblib.load(MODEL_PATH)
encoder = joblib.load(ENCODER_PATH)
final_features = joblib.load(FEATURES_PATH)

cat_cols = ["state", "proto", "service"]

def predict_flow(flow_features):
    X_live = pd.DataFrame([flow_features])
    X_live = X_live[final_features]
    X_live = X_live.fillna(0)
    # encode categorical columns
    encoded = encoder.transform(X_live[cat_cols])

    # assign back column by column as numeric
    for i, col in enumerate(cat_cols):
        X_live[col] = encoded[:, i]
        
    prediction = model.predict(X_live)[0]
    probability = model.predict_proba(X_live)[0][1]

    label = "Attack" if prediction == 1 else "Normal"
    return label, probability
