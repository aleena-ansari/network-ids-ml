# SentryNet Frontend

Lightweight React + Vite SOC dashboard for the FastAPI network intrusion detection backend.

## Local development

```sh
npm install
npm run dev
```

The frontend connects to the FastAPI backend at `http://localhost:8000` by default. To use another URL, set `VITE_API_BASE_URL` in a local `.env.local` file, then restart Vite. The checked-in backend allows cross-origin requests from the Vite dev server.

The backend API contract in `aleena-ansari/network-ids-ml` matches the frontend routes: `GET /`, `GET /alerts`, `GET /alerts/{id}`, `PUT /alerts/{id}/status`, and `POST /predict`. Start the frontend with `npm run dev` and the backend separately with Uvicorn from the backend repository.

## Data and follow-ups

- **Model artifacts are required:** the GitHub repository does not include `binary_model.pkl`, `category_model.pkl`, `model_columns.pkl`, or `data/train.csv` (they are missing/ignored). The backend imports the model files at startup, so obtain the trained artifacts or the training dataset and train the models before starting the API.
- **Categorical encoding needs a backend fix:** `train.py` one-hot encodes `protocol_type`, `service`, and `flag`, but the current `/predict` handler passes the raw category strings to `predict_row`, which reindexes to one-hot model columns. This means the current API drops those categorical values. Fix the backend to apply the same `pd.get_dummies` transformation before reindexing to `model_columns`.
- **Metrics endpoint missing:** the performance panel reads clearly labeled sample metrics from `src/data/metrics.json` (Option B from the build spec). `fetchMetrics()` is isolated in `src/api/metrics.js`; replace its sample return with a request to `/metrics` when available.
- **CSV/demo rows:** `public/data/test.csv` contains a 200-row sample from the repository's NSL-KDD test split. The form can sample a random row from it or accept a local CSV upload. It reads the first 41 fields and ignores the dataset's attack label and difficulty columns. NSL-KDD does not contain source/destination IPs; the form keeps the entered IP values for submitted samples.
- **Raw feature persistence:** submitted rows are kept in browser session storage so their new alert detail can show the input. Historical alerts loaded from the backend have no raw feature snapshot; persisting the input on the backend `Alert` model would close this gap.
- Confirm the backend's actual port and the feature list with its maintainer.

No authentication, role switching, or auto-block controls are included. Alert state is analyst-only triage.
