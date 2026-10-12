import pandas as pd
from sklearn.datasets import fetch_kddcup99
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

print("1. 실제 글로벌 보안 데이터(KDD Cup 99) 다운로드 중...")
kdd = fetch_kddcup99(percent10=True, as_frame=True)
df = kdd.frame

print("2. 데이터 전처리 및 Feature/Target 세팅...")
features = ['duration', 'protocol_type', 'src_bytes', 'dst_bytes', 'count']
X = df[features].copy()

le = LabelEncoder()
X['protocol_type'] = le.fit_transform(X['protocol_type'])
y = df['labels'].apply(lambda x: 0 if x == b'normal.' else 1).astype(int)

print("3. AI 모델 학습 시작 (억지 100% 방지)...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=30, random_state=42)
model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test) * 100
print(f"✅ 실제 데이터 기반 학습 완료! 예측 정확도: {accuracy:.2f}%")
