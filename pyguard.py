from flask import Flask, request, jsonify
from flask_cors import CORS
import re
from collections import Counter, defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

app = Flask(__name__)
CORS(app)

MODEL_PATH = "anomaly_model.pkl"
TRAIN_FILE = "apache_train.log"

LOG_PATTERN = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>.*?)\] "(?P<method>\w+) (?P<url>.*?) HTTP/.*?" (?P<status>\d{3})'

CRITICAL_KEYWORDS = ["admin","login","config","shell",".env","setup"]

ATTACK_PATTERNS = {
    "SQL Injection": r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(\bOR\b.+\=)",
    "XSS": r"(<script>|%3Cscript|alert\()",
    "Path Traversal": r"(\.\./\.\./|\.\.\\)",
    "Command Injection": r"(;|\|\||&&)\s*(cat|ls|whoami|id)"
}

RISK_WEIGHTS = {
    "SQL Injection":8,
    "XSS":6,
    "Path Traversal":7,
    "Command Injection":9,
    "Critical Path":3,
    "404 Scan":2
}

# ---------- TRAIN MODEL ----------
def train_model_from_file(filepath):
    if not os.path.exists(filepath):
        return None

    vecs=[]
    with open(filepath,encoding="utf-8",errors="ignore") as f:
        for line in f:
            m=re.search(LOG_PATTERN,line)
            if not m: continue
            url=m.group("url")
            status=int(m.group("status"))
            vecs.append([
                len(url),
                status,
                url.count("/"),
                int("admin" in url),
                int("login" in url)
            ])

    if len(vecs)<20: return None

    model=IsolationForest(contamination=0.1)
    model.fit(np.array(vecs))
    joblib.dump(model,MODEL_PATH)
    return model

# ---------- LOAD ----------
model=None
if os.path.exists(MODEL_PATH):
    model=joblib.load(MODEL_PATH)
else:
    model=train_model_from_file(TRAIN_FILE)

def severity(score):
    if score>=12:return "HIGH"
    if score>=5:return "MEDIUM"
    return "LOW"

# ---------- API ----------
@app.route('/analyze',methods=['POST'])
def analyze():
    data=request.get_json(force=True)
    raw=data.get("logs","")
    threshold=int(data.get("threshold",10))

    ip_count=Counter()
    ip_risk=defaultdict(int)
    incidents=[]

    for line in raw.splitlines():
        m=re.search(LOG_PATTERN,line)
        if not m: continue

        ip=m.group("ip")
        url=m.group("url").lower()
        status=m.group("status")

        label=None
        for name,pat in ATTACK_PATTERNS.items():
            if re.search(pat,url,re.I):
                label=name; break

        if not label:
            if any(k in url for k in CRITICAL_KEYWORDS):
                label="Critical Path"
            elif status=="404":
                label="404 Scan"
            else:
                continue

        ip_count[ip]+=1
        ip_risk[ip]+=RISK_WEIGHTS[label]

        incidents.append({
            "ip":ip,
            "url":url,
            "status":status,
            "type":label
        })

    blacklist=[ip for ip,c in ip_count.items() if c>=threshold]

    risk_summary={ip:{"score":s,"severity":severity(s)}
                  for ip,s in ip_risk.items()}

    # ML anomaly
    feats=[];ips=[]
    for ip in ip_count:
        urls=[i["url"] for i in incidents if i["ip"]==ip]
        stats=[i["status"] for i in incidents if i["ip"]==ip]
        types=[i["type"] for i in incidents if i["ip"]==ip]

        feats.append([
            ip_count[ip],
            ip_risk[ip],
            len(set(urls)),
            stats.count("404")/len(stats),
            len(set(types))
        ])
        ips.append(ip)

    anomaly={}
    if model and feats:
        preds=model.predict(np.array(feats))
        for ip,p in zip(ips,preds):
            anomaly[ip]="ANOMALOUS" if p==-1 else "NORMAL"

    return jsonify({
        "status":"success",
        "total_incidents":len(incidents),
        "incidents":incidents,
        "threat_actors":ip_count.most_common(5),
        "blacklisted":blacklist,
        "risk_analysis":risk_summary,
        "ml_anomaly":anomaly
    })

if __name__=="__main__":
    print("API running http://127.0.0.1:5000")
    app.run(debug=True)
