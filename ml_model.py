# app.py
import numpy as np
import pandas as pd
import streamlit as st
import altair as alt

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score

from pyod.models.ecod import ECOD
try:
    from pyod.utils.utility import standardizer
except Exception:
    from sklearn.preprocessing import StandardScaler
    def standardizer(X, X_t=None, keep_scalar=False):
        scaler = StandardScaler().fit(X)
        if X_t is None:
            return (scaler.transform(X), scaler) if keep_scalar else scaler.transform(X)
        Xt = scaler.transform(X_t)
        return (scaler.transform(X), Xt, scaler) if keep_scalar else (scaler.transform(X), Xt)

st.set_page_config(page_title="SIEM Demo", layout="wide")
np.random.seed(42)

# ---------- Generators (same as script, parameterized) ----------
def make_incidents(n=2000, start="2025-01-01"):
    rng = np.random.default_rng(42)
    start_ts = pd.to_datetime(start)
    ts = start_ts + pd.to_timedelta(rng.integers(0, 60*24*30, size=n), unit="m")
    severity = rng.integers(1, 6, size=n)
    is_true = rng.choice([0,1], size=n, p=[0.3, 0.7])
    det_delay = np.clip(rng.normal(6, 3, size=n), 0.1, 72)
    rsp_delay = np.clip(rng.normal(24, 10, size=n), 0.5, 168)
    detected_at = ts + pd.to_timedelta(det_delay, unit="h")
    responded_at = detected_at + pd.to_timedelta(rsp_delay, unit="h")
    flip = rng.choice([0,1], size=n, p=[0.9, 0.1])
    is_detected = is_true ^ flip
    attack = rng.choice(["phishing","bruteforce","malware","misconfig","insider","other"], size=n, p=[0.2,0.15,0.25,0.15,0.1,0.15])
    control = rng.choice(["CIS-1.1","CIS-2.4","PCI-10.6","NIST-AC-7","ISO-A.12", None], size=n, p=[0.16,0.16,0.22,0.16,0.16,0.14])
    bytes_ = np.clip(rng.normal(3e5, 1.5e5, size=n), 1e4, 1.2e6).astype(int)
    source = rng.choice(["fw","edr","ids","app","cloud"], size=n, p=[0.2,0.25,0.15,0.25,0.15])
    remediation_time = (responded_at - detected_at).total_seconds()/3600.0
    return pd.DataFrame({
        "incident_id": np.arange(n),
        "timestamp": ts,
        "severity": severity,
        "remediation_time": remediation_time,
        "is_true_threat": is_true,
        "is_detected": is_detected,
        "detected_at": detected_at,
        "responded_at": responded_at,
        "attack_vector": attack,
        "compliance_control": control,
        "ingested_bytes": bytes_,
        "source": source
    }).sort_values("timestamp").reset_index(drop=True)

def make_ueba(m=6000, start="2025-01-01", contamination=0.05):
    rng = np.random.default_rng(43)
    start_ts = pd.to_datetime(start)
    ts = start_ts + pd.to_timedelta(rng.integers(0, 60*24*30, size=m), unit="m")
    entity = [f"user_{i}" for i in rng.integers(1, 1000, size=m)]
    behavior = np.clip(rng.normal(50, 10, size=m), 10, 100)
    evph = np.clip(rng.normal(20, 8, size=m), 1, 120)
    flog = np.clip(rng.poisson(0.6, size=m), 0, 30)
    sacc = rng.choice([0,1], size=m, p=[0.92,0.08])
    idx = rng.choice(np.arange(m), size=int(contamination*m), replace=False)
    behavior[idx] = np.clip(behavior[idx] + rng.normal(35, 10, size=len(idx)), 30, 100)
    evph[idx] = np.clip(evph[idx] + rng.normal(40, 12, size=len(idx)), 5, 200)
    flog[idx] = np.clip(flog[idx] + rng.poisson(6, size=len(idx)), 0, 50)
    sacc[idx] = 1
    df = pd.DataFrame({
        "timestamp": ts,
        "entity": entity,
        "behavior_score": behavior,
        "events_per_hour": evph,
        "failed_logins": flog,
        "sensitive_access": sacc
    }).sort_values("timestamp").reset_index(drop=True)
    feats = df[["behavior_score","events_per_hour","failed_logins","sensitive_access"]].fillna(0.0).values
    Xo, scaler = standardizer(feats, keep_scalar=True)
    model = ECOD(contamination=contamination)
    model.fit(Xo)
    df["anomaly_label"] = model.predict(scaler.transform(feats))
    return df

# ---------- Sidebar controls ----------
st.sidebar.header("Controls")
n_inc = st.sidebar.slider("Incidents", 500, 5000, 2000, 100)
n_ueba = st.sidebar.slider("UEBA events", 1000, 20000, 6000, 500)
contam = st.sidebar.slider("UEBA contamination", 0.01, 0.15, 0.05, 0.01)

# ---------- Data ----------
inc = make_incidents(n=n_inc)
ueba = make_ueba(m=n_ueba, contamination=contam)

# ---------- Metrics ----------
def m_detected(df): return int((df["is_detected"] == 1).sum())
def m_mttd(df): return float((pd.to_datetime(df["detected_at"]) - pd.to_datetime(df["timestamp"])).dt.total_seconds().div(3600).mean())
def m_mttr(df): return float((pd.to_datetime(df["responded_at"]) - pd.to_datetime(df["detected_at"])).dt.total_seconds().div(3600).mean())
def m_fpr(df):
    alerts = df[df["is_detected"] == 1]
    return float((alerts["is_true_threat"] == 0).mean()) if len(alerts) else float("nan")
def m_severity(df):
    alerts = df[df["is_detected"] == 1]
    vc = alerts["severity"].value_counts().reindex(range(1,6), fill_value=0)
    return pd.DataFrame({"severity":[1,2,3,4,5], "count":[int(vc.loc[i]) for i in range(1,6)]})
def m_ingestion(df):
    if df.empty: return 0.0
    hours = max((df["timestamp"].max() - df["timestamp"].min()).total_seconds()/3600.0, 1e-6)
    return float(df["ingested_bytes"].sum()/1_000_000.0/hours)
def m_attack_share(df):
    cats = ["phishing","bruteforce","malware","misconfig","insider","other"]
    vc = df["attack_vector"].value_counts()
    tot = max(vc.sum(), 1)
    return pd.DataFrame({"vector":cats, "share":[float(vc.get(k,0)/tot) for k in cats]})
def m_compliance(df):
    catalog = ["CIS-1.1","CIS-2.4","PCI-10.6","NIST-AC-7","ISO-A.12"]
    present = set(df["compliance_control"].dropna().unique())
    return float(len(present)/len(catalog))
def m_corr_precision(ueba_df):
    if ueba_df.empty: return float("nan")
    u = ueba_df.sort_values(["entity","timestamp"]).copy()
    roll = (u.groupby("entity").apply(lambda g: g.set_index("timestamp")["failed_logins"].rolling("1h").sum())
            .reset_index(level=0, drop=True))
    u["failed_rolling"] = roll.values
    cond = (u["failed_rolling"] >= 5) & (u["sensitive_access"] == 1)
    alerts = u[cond]
    if alerts.empty: return float("nan")
    rng = np.random.default_rng(99)
    tps = rng.choice([0,1], size=len(alerts), p=[0.3,0.7]).sum()
    return float(tps/len(alerts))

det_count = m_detected(inc)
mttd = m_mttd(inc)
mttr = m_mttr(inc)
fpr = m_fpr(inc)
sev_df = m_severity(inc)
ing = m_ingestion(inc)
atk_df = m_attack_share(inc)
cov = m_compliance(inc)
corr = m_corr_precision(ueba)
ueba_anoms = int(ueba["anomaly_label"].sum())

# ---------- Header ----------
st.title("Interactive SIEM Demo")
st.caption("Synthetic incidents + UEBA with 10 KPIs and anomaly detection")

# ---------- KPI tiles ----------
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Detected Incidents", f"{det_count}")
col2.metric("MTTD (h)", f"{mttd:.2f}")
col3.metric("MTTR (h)", f"{mttr:.2f}")
col4.metric("False Positive Rate", f"{fpr:.3f}" if fpr==fpr else "—")
col5.metric("Ingestion (MB/h)", f"{ing:.2f}")

col6, col7, col8, col9, col10 = st.columns(5)
col6.metric("UEBA Anomalies", f"{ueba_anoms}")
col7.metric("Corr. Precision", f"{corr:.3f}" if corr==corr else "—")
col8.metric("Compliance Coverage", f"{cov:.3f}")
col9.metric("Incidents", f"{len(inc):,}")
col10.metric("UEBA Events", f"{len(ueba):,}")

# ---------- Charts ----------
left, right = st.columns(2)

with left:
    st.subheader("Severity Volume")
    chart = alt.Chart(sev_df).mark_bar(color="#4c78a8").encode(
        x=alt.X("severity:O", title="Severity"),
        y=alt.Y("count:Q", title="Count")
    )
    st.altair_chart(chart, use_container_width=True)

with right:
    st.subheader("Attack Vector Share")
    pie = alt.Chart(atk_df).mark_arc(innerRadius=60).encode(
        theta="share:Q",
        color=alt.Color("vector:N", legend=alt.Legend(orient="bottom"))
    )
    st.altair_chart(pie, use_container_width=True)

st.subheader("UEBA Anomalies Over Time")
ueba_hourly = (ueba.set_index("timestamp")["anomaly_label"]
               .resample("1h").sum().reset_index())
line = alt.Chart(ueba_hourly).mark_line(color="#d95f02").encode(
    x=alt.X("timestamp:T", title="Time"),
    y=alt.Y("anomaly_label:Q", title="Anomalies per hour")
)
st.altair_chart(line, use_container_width=True)

st.subheader("Alert Feed")
alerts = inc[inc["is_detected"] == 1].copy()
alerts["MTTD_h"] = (alerts["detected_at"] - alerts["timestamp"]).dt.total_seconds()/3600
st.dataframe(
    alerts[["incident_id","timestamp","severity","attack_vector","MTTD_h"]]
    .sort_values("timestamp").tail(200),
    use_container_width=True, height=300
)
