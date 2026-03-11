from fastapi import FastAPI
from app.schema import URLRequest
from app.predictor import predict_url
from app.threat_feeds import load_threat_feeds

app = FastAPI()


@app.on_event("startup")
def startup_event():
    load_threat_feeds()


@app.get("/")
def home():
    return {"message": "Phishing Detection API running"}


@app.post("/scan-url")
def scan_url(data: URLRequest):

    prediction, probability, features, threat_source = predict_url(data.url)

    prob = float(probability)

    if prediction == -1:

        possible = ["Suspicious", "Phishing"]

        if prob >= 0.7:
            result = possible[1]
            flag = "red"
        else:
            result = possible[0]
            flag = "orange"

    else:
        result = "Legitimate"
        flag = "green"

    return {
        "url": data.url,
        "prediction": result,
        "probability": round(prob, 4),
        "risk_flag": flag,
        "features": features,
        "threat_feed": threat_source
    }