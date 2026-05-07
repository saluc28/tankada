"""
Tankada Demo Dashboard — backend server
Run: python server.py
Open: http://localhost:8090

LLM providers (set via env vars):
  LLM_PROVIDER=ollama    (default) — requires Ollama running locally
  LLM_PROVIDER=openai   — requires LLM_API_KEY=sk-...
  LLM_PROVIDER=anthropic — requires LLM_API_KEY=sk-ant-...
  LLM_MODEL=<model>      — overrides the default model for the provider
"""
import json, jwt, datetime, urllib.request, urllib.error, sys, warnings, os
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

warnings.filterwarnings("ignore")

JWT_SECRET  = "dev-secret-change-in-production"
GATEWAY_URL = "http://localhost:8080"
PORT = 8090

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama").lower()
LLM_API_KEY  = os.getenv("LLM_API_KEY", "")
_DEFAULT_MODELS = {
    "ollama":    "qwen2.5:7b",
    "openai":    "gpt-4o-mini",
    "anthropic": "claude-haiku-4-5-20251001",
}
LLM_MODEL = os.getenv("LLM_MODEL", _DEFAULT_MODELS.get(LLM_PROVIDER, "gpt-4o-mini"))

AGENTS = {
    "analyst": {"roles": ["analyst"],  "scopes": ["orders:read"]},
    "admin":   {"roles": ["admin"],    "scopes": ["orders:read", "users:read", "payments:read"]},
}

SYSTEM_PROMPT = """You are a business data assistant with access to the sql_database tool.

Database schema:
- products(id, name, category, price, stock, created_at)
- orders(id, tenant_id, user_id, product, amount, status, created_at)
- users(id, tenant_id, email, name, created_at)

Rules for every query:
1. Always include a WHERE clause with specific values
2. Select only needed columns — never SELECT *
3. Never attempt DELETE, DROP, UPDATE, INSERT
4. The "orders" and "users" tables have a tenant_id column — always add AND tenant_id = 'tenant_1' to their WHERE clause. Example: WHERE status = 'completed' AND tenant_id = 'tenant_1'
5. The "products" table does NOT have a tenant_id column — never add tenant_id to queries on products.

If a query is blocked, rewrite it following the rules above.
Always answer in English."""


def make_token(agent_type: str) -> str:
    cfg = AGENTS.get(agent_type, AGENTS["analyst"])
    now = datetime.datetime.now(datetime.timezone.utc)
    return jwt.encode({
        "sub": f"{agent_type}-agent", "iss": "tankada",
        "agent_id": f"{agent_type}-agent", "tenant_id": "tenant_1",
        "roles": cfg["roles"], "scopes": cfg["scopes"],
        "iat": now, "exp": now + datetime.timedelta(hours=8),
    }, JWT_SECRET, algorithm="HS256")


def call_gateway(query: str, token: str) -> dict:
    payload = json.dumps({"query": query}).encode()
    req = urllib.request.Request(
        f"{GATEWAY_URL}/v1/query", data=payload,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())
    except Exception as ex:
        return {"error": str(ex)}


def build_llm():
    if LLM_PROVIDER == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model=LLM_MODEL, api_key=LLM_API_KEY, temperature=0)
    elif LLM_PROVIDER == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=LLM_MODEL, api_key=LLM_API_KEY, temperature=0)
    else:
        from langchain_ollama import ChatOllama
        return ChatOllama(model=LLM_MODEL, temperature=0)


def run_agent(task: str, agent_type: str) -> dict:
    from langchain_core.tools import tool
    from langgraph.prebuilt import create_react_agent

    token = make_token(agent_type)
    steps = []

    @tool
    def sql_database(query: str) -> str:
        """Execute a SQL SELECT query on the company database.
        Schema: products(id,name,category,price,stock), orders(id,tenant_id,user_id,product,amount,status), users(id,tenant_id,email,name).
        Always use a WHERE clause. Never SELECT *. Never use DELETE/DROP/UPDATE.
        Only orders and users have a tenant_id column — add AND tenant_id = 'tenant_1' only for those tables. Never add tenant_id to products queries."""
        gw = call_gateway(query, token)
        exec_error = gw.get("error")
        step = {
            "sql":        query,
            "decision":   "error" if exec_error and not gw.get("decision") else gw.get("decision", "deny"),
            "risk_score": gw.get("risk_score", 0),
            "risk_level": gw.get("risk_level", "unknown"),
            "reasons":    gw.get("reasons", [exec_error] if exec_error and not gw.get("decision") else []),
            "result":     gw.get("result"),
            "latency_ms": gw.get("latency_ms", 0),
            "error":      exec_error,
        }
        steps.append(step)

        if step["error"]:
            return f"[ERROR] {step['error']}"
        if step["decision"] == "deny":
            reasons = "; ".join(step["reasons"]) or "policy violation"
            return f"[BLOCKED by Tankada] {reasons}. Rewrite the query following the rules."

        data = step["result"] or {}
        rows = data.get("rows", [])
        cols = data.get("columns", [])
        if not rows:
            return "[OK] No results found."
        header = " | ".join(cols)
        lines  = [" | ".join(str(v) for v in row) for row in rows[:15]]
        return f"[OK] {data.get('row_count', 0)} row(s)\n{header}\n" + "\n".join(lines)

    llm   = build_llm()
    agent = create_react_agent(llm, [sql_database], prompt=SYSTEM_PROMPT)

    try:
        result = agent.invoke({"messages": [("human", task)]})
        answer = result["messages"][-1].content
    except Exception as ex:
        answer = f"Agent error: {ex}"

    return {"steps": steps, "answer": answer}


class Handler(BaseHTTPRequestHandler):

    def _json(self, data: dict, status: int = 200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = Path(__file__).parent / "index.html"
        if self.path in ("/", "/index.html") and path.exists():
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length))

        if self.path == "/api/agent":
            task       = body.get("task", "").strip()
            agent_type = body.get("agent_type", "analyst")
            if not task:
                self._json({"error": "empty task"}, 400); return
            result = run_agent(task, agent_type)
            self._json(result)

        elif self.path == "/api/query":
            query      = body.get("query", "").strip()
            agent_type = body.get("agent_type", "analyst")
            if not query:
                self._json({"error": "empty query"}, 400); return
            token  = make_token(agent_type)
            result = call_gateway(query, token)
            self._json(result)

        else:
            self.send_response(404); self.end_headers()

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    print(f"Dashboard → http://localhost:{PORT}")
    print(f"LLM provider: {LLM_PROVIDER} / model: {LLM_MODEL}")
    print(f"Requires: Tankada stack on :8080")
    if LLM_PROVIDER == "ollama":
        print(f"Requires: Ollama on :11434 with model '{LLM_MODEL}'")
    HTTPServer(("", PORT), Handler).serve_forever()
