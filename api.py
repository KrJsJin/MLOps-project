from fastapi import FastAPI
from pydantic import BaseModel
import pandas as pd
from sklearn.datasets import fetch_kddcup99
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

app = FastAPI(title="클라우드 네트워크 침입 탐지 API")

print("보안 AI 모델 준비 중...")
kdd = fetch_kddcup99(percent10=True, as_frame=True)
df = kdd.frame.sample(10000, random_state=42)

X = df[['duration', 'protocol_type', 'src_bytes', 'dst_bytes', 'count']].copy()
le = LabelEncoder()
X['protocol_type'] = le.fit_transform(X['protocol_type'])
y = df['labels'].apply(lambda x: 0 if x == b'normal.' else 1).astype(int)

model = RandomForestClassifier(n_estimators=30, random_state=42)
model.fit(X, y)
print("API 준비 완료!")

class NetworkLog(BaseModel):
    duration: int
    protocol_type: int
    src_bytes: int
    dst_bytes: int
    count: int

@app.post("/predict")
def predict_anomaly(log: NetworkLog):
    input_df = pd.DataFrame([[
        log.duration, log.protocol_type, log.src_bytes, log.dst_bytes, log.count
    ]], columns=['duration', 'protocol_type', 'src_bytes', 'dst_bytes', 'count'])

    risk_prob = model.predict_proba(input_df)[0][1] * 100
    action = "네트워크 차단(Block)" if risk_prob >= 80 else "정상 통과(Allow)"

    return {"위험도_점수": f"{risk_prob:.1f}%", "제어_명령": action}
