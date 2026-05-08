# Contributing to Tankada

## Running the project locally

**Prerequisites:** Docker, Docker Compose, Python 3.10+, Go 1.22+, OPA.

```bash
# Start all services
cd deploy
DOCKER_BUILDKIT=0 docker compose up -d

# Verify everything is up
docker compose ps
```

The gateway listens on `http://localhost:8080`. See `README.md` for how to generate a JWT and send your first query.

**Run the tests:**

```bash
# Analyzer (Python)
cd analyzer
pytest test_analyzer.py -q

# Gateway (Go)
cd gateway
go test ./...

# Policies (OPA)
opa test policies/ -v
```

---

## Adding a policy rule

Policies live in `policies/query.rego`. Each deny rule follows this pattern:

```rego
deny contains reason if {
    # your condition here
    reason := "human-readable message the agent receives"
}
```

Add a matching test in `policies/query_test.rego`:

```rego
test_deny_your_rule if {
    inp := object.union(base_input, {"analysis": object.union(base_input.analysis, {
        "your_field": true,
    })})
    "human-readable message the agent receives" in query.deny with input as inp with data.templates as default_templates
}
```

Run `opa test policies/ -v` to confirm your test passes before opening a PR.

If your rule uses a new analysis field, add it to `analyzer/analyzer.py` and cover it in `analyzer/test_analyzer.py`.

---

## Opening a pull request

1. Fork the repo and create a branch from `main`
2. Make your change. One logical change per PR.
3. Run the full test suite (see above) and confirm it is green
4. Open a PR with a short description of what the change does and why

For substantial changes (new detection rules, new endpoints, schema changes) open an issue first to discuss the approach.
