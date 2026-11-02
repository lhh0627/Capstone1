# Wazuh IOC Console

Wazuh Indexer -> IOC extraction (IP, domain, MD5/SHA1/SHA256) -> Claude verdict -> analyst console.

## Run
    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env   # fill in values
    export $(grep -v '^#' .env | xargs)
    uvicorn app:app --host 127.0.0.1 --port 8000
Open http://127.0.0.1:8000

## Notes
- Needs read access to the Wazuh Indexer (port 9200) with a read-only user on `wazuh-alerts-*`.
- Private/loopback IPs are skipped. Domain matching uses a fixed TLD list; extend `RE_DOM` as needed.
- Log text is sent to the Anthropic API. Redact sensitive fields first if your policy requires it.
- "Block" currently only sets a status. To enforce it, call the Wazuh Manager API active-response endpoint from `set_status`.
- No login yet. Keep it on localhost or put it behind a reverse proxy with auth.
