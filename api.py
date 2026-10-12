# model.py (9개 피처 기반 최종 보안 모델)
import os
import kagglehub
import pandas as pd
import numpy as np
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

print("1. 캐글 웹 서버 로그 원본 다운로드 중...")
path = kagglehub.dataset_download("eliasdabbas/web-server-access-logs")
log_file = os.path.join(path, "access.log")

print("2. 9개의 다중 보안 피처(Multi-Feature) 추출 중...")
log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<request>.*?)" '
    r'(?P<status>\d+) (?P<bytes>\S+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"'
)

data = []
with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
    for _ in range(50000): 
        line = f.readline()
        if not line: break
        match = log_pattern.match(line)
        if match: data.append(match.groupdict())

df = pd.DataFrame(data)

df['time'] = pd.to_datetime(df['time'].str.split(' ').str[0], format='%d/%b/%Y:%H:%M:%S', errors='coerce')
df['login_hour'] = df['time'].dt.hour.fillna(12).astype(int)
df['user_agent_type'] = df['user_agent'].str.lower().apply(lambda x: 1 if any(b in str(x) for b in ['bot', 'spider', 'crawler', 'curl']) else 0)
df['ip_freq'] = df['ip'].map(df['ip'].value_counts())
df['status'] = pd.to_numeric(df['status'], errors='coerce').fillna(200)
df['is_error'] = np.where(df['status'] >= 400, 1, 0)
df['ip_error_count'] = df.groupby('ip')['is_error'].transform('sum')
df['is_post_method'] = df['request'].str.upper().apply(lambda x: 1 if isinstance(x, str) and 'POST' in x else 0)
df['is_sus_path'] = df['request'].str.lower().apply(lambda x: 1 if isinstance(x, str) and any(k in x for k in ['admin', 'login', '.env', 'config']) else 0)
df['url_length'] = df['request'].str.len().fillna(0)
df['is_empty_referer'] = np.where((df['referer'] == '-') | (df['referer'] == ''), 1, 0)
df['bytes_sent'] = pd.to_numeric(df['bytes'], errors='coerce').fillna(0)

# 해킹 룰셋 (Target 설정)
df['is_anomaly'] = np.where(
    (df['ip_error_count'] > 5) | 
    ((df['is_sus_path'] == 1) & (df['status'] >= 400)) | 
    (df['ip_freq'] > 50) | 
    ((df['url_length'] > 100) & (df['is_error'] == 1)) | 
    ((df['user_agent_type'] == 1) & (df['is_empty_referer'] == 1)), 
    1, 0
)

if df['is_anomaly'].sum() < 20: df.loc[df.sample(frac=0.1, random_state=42).index, 'is_anomaly'] = 1 

print("3. 최종 AI 모델 학습 시작...")
features = ['user_agent_type', 'login_hour', 'ip_freq', 'ip_error_count', 'is_post_method', 'is_sus_path', 'url_length', 'is_empty_referer', 'bytes_sent']
X = df[features]
y = df['is_anomaly']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X_train, y_train)

print(f"✅ 9개 다중 피처 기반 AI 모델 학습 완료! 예측 정확도: {model.score(X_test, y_test) * 100:.1f}%")
