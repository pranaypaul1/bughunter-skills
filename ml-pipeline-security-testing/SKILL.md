---
name: ml-pipeline-security-testing
description: AI/ML pipeline and MLOps infrastructure attack surface — testing beyond the documented REST API to find the ML-specific services (inference endpoints, MLflow/Kubeflow/model-registry tracking servers, Jupyter notebooks, TensorBoard, model-serving runtimes) that a narrowly-scoped API pentest misses entirely, plus the ML-specific vuln classes they expose: prediction-score oracle attacks for classifier evasion, unauthenticated MLOps-tool model/data exfiltration, notebook-kernel RCE, and training-pipeline poisoning for persistent silent compromise. Use this during Phase 1/3 (Recon/Vulnerability Testing) of bughunting-workflow whenever a target's scope includes an "AI feature," "ML model," "fraud detection," "recommendation engine," or any product description mentioning machine learning — the interesting vulnerabilities live in the MLOps tooling around the model, not the documented API in front of it. Also trigger on mentions of MLflow, Jupyter kernel RCE, model inference API, fraud score bypass, model poisoning, ML red team, AI red team, TensorBoard, or model registry exposure.
---

# ML Pipeline / MLOps Attack Surface Testing

General technique library for red-teaming machine learning infrastructure end-to-end — not just the customer-facing inference API but the whole MLOps stack behind it. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* MLOps tool or ML-specific bug class than what's already recorded.

## Core theory

A scoped API pentest treats "the ML feature" as one REST endpoint and stops there. That's exactly why ML systems are systematically under-tested: **"ML systems don't carve cleanly at API boundaries. The interesting vulnerabilities never live where people think they do."** The real attack surface is everything that had to exist to build, train, monitor, and redeploy that one endpoint:

- An **inference API** that, beyond just returning a decision, often leaks the raw model score/confidence — turning "is this blocked or not" into a continuous oracle an attacker can binary-search against.
- **MLOps tracking/registry tooling** (MLflow, Kubeflow, Weights & Biases, SageMaker, Vertex AI) that stores hyperparameters, model artifacts/weights, training datasets, and experiment metadata — and is disproportionately deployed with no authentication at all, because it's treated as "internal tooling" rather than a production surface.
- **Interactive notebook servers** (Jupyter, JupyterHub, Zeppelin, Databricks notebooks) left reachable and unauthenticated, giving direct arbitrary code execution as whatever service account runs data science workloads — which usually has read access to credentials, training data, and the retraining pipeline itself.
- The **retraining/pipeline code** that periodically ingests new data and redeploys a model — a much higher-value persistence target than a webshell, because a modified training script keeps quietly degrading or backdooring every future model version without needing repeated access.

Treat any of these found alongside a model-serving product as one connected engagement, not four unrelated findings — the escalation path (leaked score → evasion; leaked artifacts → model theft/PII; notebook RCE → credential theft; pipeline tampering → persistence) is usually a single walkable chain across a handful of adjacent ports on the same host/cluster.

## Trigger technique: full-port scan for ML-specific services, not just the documented API

Don't stop at the one port the program describes as "the API." Run a full port sweep (`rustscan`/`nmap -p-`) against every host tied to the ML feature and specifically check for these common MLOps service signatures:

| Port (default) | Service | What it usually gives you unauthenticated |
|---|---|---|
| 5000 | Flask/Werkzeug (generic — often the inference API itself) | raw model scores, feature names/importances, thresholds |
| 5001 / 5002 | MLflow Tracking Server | full run history, hyperparameters, model artifacts, training data refs |
| 8888 | Jupyter Notebook/Lab | kernel API → arbitrary code execution as the data-science service account |
| 6006 | TensorBoard | training metrics, sometimes embedded/profiling data with PII |
| 8501 | TensorFlow Serving REST | model metadata, sometimes raw model files via misconfigured static serving |
| 8000 / 8080 | Triton Inference Server, generic model-serving | model repository listing, config protobufs |
| 6443 / 8443 | Kubeflow / Kubernetes-fronted ML pipelines | pipeline definitions, sometimes cluster-wide creds if RBAC is loose |
| 8265 | Ray dashboard | cluster job submission — can itself be an RCE vector |

Any of these responding without auth on a host associated with an "AI/ML" scoped feature is worth escalating immediately — this class of tooling defaults to open far more often than a mainstream web framework does, because teams assume "nobody will find the MLflow port."

## Recorded techniques

### 1. Full engagement chain: score-oracle evasion → unauthenticated MLflow exfiltration → Jupyter kernel RCE → training-pipeline poisoning
Source: [What a Real AI Red Team Engagement Actually Looks Like — From API Recon to RCE on an ML Pipeline](https://sn0xsharma.medium.com/what-a-real-ai-red-team-engagement-actually-looks-like-from-api-recon-to-rce-on-a-ml-pipeline-4aa01caca3a1)

**Where:** a fraud-detection ML product. Scope on paper was "the inference API"; the actual attack surface turned out to span five open ports, three of which were ML-specific infrastructure a narrowly-scoped assessment would never touch: `5000` (Flask inference API), `5001` (MLflow Tracking Server), `8888` (Jupyter Notebook 6.5.4), alongside the boring `22`/`80`.

**Stage 1 — API info disclosure (port 5000):** `/model/info` returned feature names + importances, the classification threshold (`0.72`), model version/training date, and the MLflow run ID tying this deployed model back to its MLflow record (the pivot into Stage 3). Prediction responses additionally echoed the raw model output, e.g. `"fraud_score": 0.94` — a continuous score, not just an allow/block decision.

**Stage 2 — score-oracle evasion via binary search:** because the raw score was visible, the attacker could treat the model as a numeric oracle: adjust one feature (`velocity_score`) and watch the score move. Reducing `velocity_score` from `9` to `5` dropped `fraud_score` from `0.9401` to `0.6977` — below the `0.72` threshold — while every other high-risk indicator on the transaction was left unchanged. Full bypass confirmed in 5 requests via binary search on that one feature.

**Stage 3 — unauthenticated MLflow exploitation (port 5001):**
```
GET /api/2.0/mlflow/experiments/list
POST /api/2.0/mlflow/runs/search
GET /api/2.0/mlflow/artifacts/list?run_id=8fa3bc91d4e2
GET /get-artifact?run_uuid=8fa3bc91d4e2&path=data/training_sample.csv
```
The exposed MLflow instance required no auth on any of the above and handed over the complete hyperparameter set (`n_estimators`, `max_depth`, `learning_rate`, `scale_pos_weight`), the actual model artifact (`model.xgb`, 2.8MB — enough for full local reconstruction of the production model), the full training dataset (84,201 real transactions with user IDs, amounts, and fraud labels — a straight PII/data breach on its own), and complete experiment/deployment metadata.

**Stage 4 — RCE via unauthenticated Jupyter kernel API (port 8888):** Jupyter's kernel WebSocket API was reachable with no auth, giving direct arbitrary Python execution as the `data-team` service account:
```python
ws = websocket.create_connection(f"ws://<target>:8888/api/kernels/{KERNEL_ID}/channels")
```
```json
{"header": {"msg_type": "execute_request"}, "content": {"code": "import os; print(os.popen('whoami').read())"}}
```
From there: full home-directory access surfaced `.mlflow_credentials` and the retraining script `retrain_pipeline.py`.

**Stage 5 — escalation to persistence via pipeline poisoning:** rather than stopping at RCE, the demonstrated escalation was modifying `retrain_pipeline.py` itself — injecting poisoned logic into the *next* scheduled retraining run. Root cause: the retraining job runs unreviewed, on a schedule, with whatever permissions the compromised service account has — no code-review/CI gate exists between "attacker has a shell" and "attacker's code becomes the next production model." This creates "persistent silent poisoning": a backdoor that degrades or corrupts every future model version without needing repeated attacker access, far harder to detect than a webshell since it looks like normal training-data drift.

**Impact framing for report:** stack the full chain rather than reporting each stage separately — model theft (weights + hyperparameters), a straight data breach (84k real transactions w/ user identifiers), a deterministic fraud-detection bypass, infrastructure RCE with credential access, and a persistence/poisoning vector into all future model versions. The report's core argument: "a scoped pentest (API only) finds a minor info-disclosure; a red-team engagement spanning the whole ML pipeline finds RCE, model exfiltration, PII loss, and persistent compromise — scope kills ML security assessments."

**Generalize note:** whenever a target's scope mentions any AI/ML feature, push immediately for a scope broad enough to cover the *supporting* infrastructure, not just the customer-facing endpoint — or at minimum, port-scan the full host/cluster the ML feature lives on and check every port in the trigger-technique table above. A leaked raw score/confidence value on any classifier-backed endpoint (fraud, spam, content moderation, risk-scoring) is always worth a binary-search evasion attempt on its own, independent of whether the rest of the MLOps stack is reachable. This same four-question checklist generalizes across MLOps tool vendors: (1) does any response leak a raw score/confidence instead of just a decision? (2) is the model registry/experiment tracker reachable with no auth? (3) is there a notebook/IDE-in-the-browser dev tool reachable with no auth? (4) if you get code execution, is there a scheduled retraining/pipeline script you can now silently modify?

### 2. Filename-suffix parser mismatch bypasses a `safe=True` model-loading gate → unsafe `torch.load()` deserialization RCE
Source: [I Found a Tiny Filename Bypass That Broke a "Safe" Loader (and Earned...)](https://freedium-mirror.cfd/https://medium.com/@xoemekk1/i-found-a-tiny-filename-bypass-that-broke-a-safe-loader-and-earned-7fc1afb70af3)

**Where:** a model-loading API that defaults to `safe=True` — intended to route `.safetensors` files through the safe Safetensors loader while explicitly rejecting/routing away from unsafe `pickle`-based PyTorch checkpoint loading (`torch.load(..., weights_only=False)`, the exact sink documented in entry #3 of `rce-exploitation-testing`). This is a distinct bug class from that skill's entry — the sink is the same, but this is how an attacker reaches it *despite* an explicit safe-loading gate meant to prevent exactly that.

**Root cause:** two different code components disagree on what "the file extension" is for the exact same filename string. A filename consisting of *only* the extension — `".safetensors"` — satisfies a naive `filename.endswith(".safetensors")` check (`True`) used by the validation/routing gate, but a `pathlib.Path(".safetensors").suffix` call used elsewhere in the loading pipeline returns an **empty string**, because Python's `pathlib` treats a leading dot with nothing before it as a hidden-file *name*, not a suffix on top of a name. The gate says "this is a Safetensors file, route it safely"; the actual loader's own extension-detection logic says "this file has no recognized extension," falls through its dispatch logic, and lands on the generic/unsafe `torch.load()` path — deserializing whatever pickle payload is actually inside.

**Exploit steps:**
1. Build a malicious PyTorch checkpoint containing an attacker-controlled pickle payload (standard `__reduce__`-based RCE gadget — see the open gap noted in `rce-exploitation-testing` entry #3's generalize note for constructing one).
2. Name it — or reference it via a sharded checkpoint's index file — using a filename that is *only* the extension: `.safetensors` (nothing before the dot).
3. Submit it to the model-loading API with the default `safe=True` parameter untouched — no need to explicitly disable the safety flag.
4. The `endswith()`-based validation gate passes the file as legitimate Safetensors content; the downstream extension-dispatch logic (`Path(...).suffix`) sees an empty suffix, skips the Safetensors branch, and falls through to unsafe deserialization — triggering RCE the moment a victim (or the service itself) loads the checkpoint.

**Discovery methodology worth generalizing on its own:** the researcher's actual method was tracing every attacker-controlled filename through the *complete* execution path and asking, at each component that touches it, "does this component interpret the string the same way the previous one did?" — then deliberately fuzzing filename edge cases most testers skip: a bare-extension name (`.hidden`-style dotfiles), `..`, and a trailing-dot name (`file.`). Any codebase with more than one place that independently parses a filename/extension (a validation layer, a routing/dispatch layer, a storage layer) is a candidate for this exact class of mismatch — `os.path.splitext()`, `pathlib.Path().suffix`, a raw string `endswith()`/`split('.')`, and a framework's own MIME-sniffing each have their own edge-case behavior on inputs like `.ext`, `file.`, `file..ext`, and multi-dot names, and no two of them are guaranteed to agree.

**Impact:** potential remote code execution the moment the malicious checkpoint is loaded — full access to environment variables, credentials, local files, and any other application data reachable by the loading process/service account. Rated Medium severity in this report (specific bounty amount undisclosed by the source), likely reflecting that exploitation requires a victim/service to actually load the attacker-supplied file rather than being immediately-unauthenticated RCE on its own — still worth reporting at the severity the program's own model-loading trust boundary implies.

**Generalize:** whenever an application exposes *any* "safe mode" file-type gate (not just ML checkpoint loaders — image-format sniffers, archive-type detectors, upload MIME allowlists all follow the same shape), test whether the validation check and the actual processing/dispatch logic call the *same* extension/type-detection function or two independently-written ones — a mismatch between them is a free bypass of whatever safety guarantee the gate exists to provide. Cross-reference `file-upload-testing`'s filename/extension-bypass catalog for the equivalent technique family on standard file-upload filters (the mechanism there is usually filter evasion via double extensions/null bytes rather than a parser-disagreement bug, but the "test every component that independently parses the filename" methodology transfers directly).

<!-- Add new recorded techniques below this line as new ML/AI-pipeline-attack writeups are processed. Keep the same structure: Where / Root cause / Exploit steps (staged) / Impact framing / Generalize note. -->
