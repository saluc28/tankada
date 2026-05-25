import logging

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from analyzer import analyze, load_schema_config, tenant_column
from models import AnalyzeRequest, QueryAnalysis

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("analyzer")

# Load the configurable tenant column from the shared schema config (default
# tenant_id). Non-fatal: the analyzer stays functional with the default.
load_schema_config()
log.info("analyzer tenant_column=%s", tenant_column())

app = FastAPI(title="Tankada Query Analyzer", version="0.1.0")


@app.post("/analyze", response_model=QueryAnalysis)
def analyze_query(req: AnalyzeRequest):
    if not req.query or not req.query.strip():
        raise HTTPException(status_code=400, detail="query cannot be empty")

    result = analyze(req.query)

    # Fail closed: if parse failed, block it at the caller side via parse_error field
    if result.parse_error:
        log.warning("parse_error sql=%r error=%s", req.query[:120], result.parse_error)

    return result


@app.get("/health")
def health():
    return {"status": "ok"}


@app.exception_handler(Exception)
async def generic_handler(request, exc):
    log.error("unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "internal error"})
