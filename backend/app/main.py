from fastapi import FastAPI

app = FastAPI(title="PRIMEVPN API", version="100.0.0")

@app.get("/healthz")
def healthz():
    return {"status":"ok","version":"100.0.0"}

@app.get("/readyz")
def readyz():
    return {"status":"ready"}
