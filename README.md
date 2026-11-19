# SentryNet

A machine-learning network intrusion detection prototype for a Security Operations Centre (SOC). It classifies network flows as normal or attack, raises alerts for analysts to review, and **never blocks traffic**.

**Status: research prototype.** It runs as a replay demo on the CICIDS2017 benchmark. It does not capture live traffic yet and is not production-ready.

## What it does

- **Random Forest** (primary detector): BENIGN vs attack, using the 78 CICIDS2017 flow features. Alert threshold: 0.2 attack probability (chosen on Thursday validation data).
- **Isolation Forest** (supplementary): flags unusual traffic for analyst review. It never creates a confirmed attack on its own.
- **Risk score** = Random Forest attack probability x 100. It is a heuristic for ordering analyst review, not a calibrated probability.
- **Attack family is not classified.** No CICIDS2017 family classifier exists yet, so attacks are labelled "unknown".
- **Alerts** are stored in SQLite with statuses: new, reviewed, false_positive, escalated.
- **React dashboard** with an alert queue and an investigation page (probability, anomaly score, detection source, MAC address, status actions).

## Evaluation (CICIDS2017)

Split by day: train Monday-Wednesday, validate and choose thresholds on Thursday, final test on Friday. Friday contains DDoS, PortScan and Bot, none of which appear in the training data, so this tests generalisation to unseen attack types.

Random Forest on Friday (threshold 0.2): precision 0.961, recall 0.412, false-positive rate 0.0092, ROC-AUC 0.973.

| Friday attack type | Random Forest recall |
|---|---|
| DDoS | 69.4% |
| PortScan | 2.2% |
| Bot | 0% |

The Random Forest is precise but misses most unseen attacks, especially PortScan and Bot.

**Isolation Forest:** at a threshold calibrated to about 1% false alarms on Thursday benign traffic, it caught about 9.6% of Friday attacks with a 3.4% false-positive rate.

**OR-combination rejected:** alerting when either model fires added only 13 attacks on Friday but 13,300 extra false alarms. The Isolation Forest is therefore kept as a review flag only.

Full results are in `backend/cic_metrics.json` and `backend/cic_hybrid_comparison.json`, and are served by `GET /metrics`.

## Run it (Windows)

Requirements: Python 3.13 and Node.js (LTS).

Backend:

    python -m venv venv
    venv\Scripts\activate
    pip install -r backend\requirements.txt
    cd backend
    uvicorn app.main:app --reload

API docs: http://127.0.0.1:8000/docs. The database `backend/alerts.db` is created on first start. To reset it, stop the backend and delete that file.

Frontend (second terminal):

    cd frontend
    npm install
    npm run dev

Open http://localhost:5173 and click **Simulate flows**.

## API

| Endpoint | Purpose |
|---|---|
| `GET /` | Health check and model settings |
| `GET /features` | The 78 feature names, in the order the models expect |
| `POST /predict` | Score one flow (78 features plus optional `src_ip`, `dst_ip`, `src_mac`). Missing or invalid values are rejected with 422 |
| `POST /simulate?count=N` | Demo only: replay recorded CICIDS2017 Friday flows (`backend/demo_flows.csv`) with made-up IPs and MACs |
| `GET /alerts`, `GET /alerts/{id}` | List and inspect alerts |
| `PUT /alerts/{id}/status` | Set status: new, reviewed, false_positive, escalated |
| `GET /metrics` | Saved offline evaluation and limitations |

## MAC addresses

For a local source, the MAC is the one supplied in `src_mac`, otherwise it is looked up in the Windows ARP table (`arp -a`). For an external source the MAC is null and the UI says "Not available - external source", because any MAC seen on the local network would belong to the router, not the remote host. In the simulated demo, IPs and MACs are fabricated.

## Repository layout

- `backend/app/` - FastAPI app (`main.py`, `cic_utils.py` model logic, `net_utils.py` IP/MAC helpers, `models.py`, `database.py`)
- `backend/cic_*.pkl` - CICIDS2017 Random Forest, Isolation Forest and feature list
- `frontend/` - React + Vite dashboard
- Root scripts: `preprocess_cic.py`, `prepare_cic_splits.py`, `train_cic.py`, `experiment_isolation.py`, `compare_cic_hybrid.py`, `make_demo_sample.py`
- Older NSL-KDD files (`train.py`, `backend/binary_model.pkl`, `backend/app/ml_utils.py`, ...) are kept as a historical baseline and are not used by the API.

## Reproducing the training

The datasets are not in the repository. Download the CICIDS2017 MachineLearningCSV files into `data/cicids/`, then run the root scripts in this order: `preprocess_cic.py`, `prepare_cic_splits.py`, `train_cic.py`, `experiment_isolation.py`, `compare_cic_hybrid.py`, `make_demo_sample.py`.

## Limitations

- Benchmark replay only: no live capture or live flow extraction. Live flows would need exactly the same 78 CICFlowMeter feature definitions.
- Friday attack families were absent from training, and PortScan and Bot are mostly missed.
- The Isolation Forest performs poorly on unseen attack families and produces many false alarms.
- No attack-family classifier for CICIDS2017.
- The threshold was chosen on Thursday, whose attack types differ from Friday's.
- Strong class imbalance; some attack types have very few records. A single split, no cross-validation, and model drift has not been demonstrated.
- The risk score is a heuristic, not a calibrated probability.
- CICIDS2017 has known labelling problems.
- Prototype backend: SQLite, no authentication, open CORS. Not production-hardened.