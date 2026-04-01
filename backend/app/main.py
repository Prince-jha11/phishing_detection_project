from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.schema import URLRequest
from app.predictor import predict_url
from app.threat_feeds import load_threat_feeds

app = FastAPI()


origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5500",
    "http://127.0.0.1:5500"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    load_threat_feeds()

@app.get("/")
def home():
    return {"message": "Phishing Detection API running"}


@app.post("/scan-url")
async def scan_url(data: URLRequest):

    prediction, probability, features, threat_source = predict_url(data.url)

    prob = float(probability)
    threat_detected = bool(threat_source)

    
    if prediction == -1:
        if prob >= 0.7:
            result = "Phishing"
            flag = "red"
        else:
            result = "Suspicious"
            flag = "orange"
    else:
        result = "Legitimate"
        flag = "green"


    if threat_detected:
        if result == "Legitimate":
            result = "Suspicious"  
            flag = "orange"
        elif result == "Suspicious":
            result = "Phishing"     
            flag = "red"
       

    return {
    "url": data.url,
    "prediction": result,
    "probability": round(prob, 4),
    "risk_flag": flag,

    "features": features,

    
    "domain_age_days": features.get("domain_age_days"),
    "domain_age_flag": features.get("age_of_domain"),

    "threat_feed": threat_source,
    "threat_detected": threat_detected
}