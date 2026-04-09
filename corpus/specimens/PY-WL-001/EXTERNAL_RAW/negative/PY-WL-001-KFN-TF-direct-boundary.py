def fetch_external(api_client):
    """Tier 4 boundary: fetches raw external data."""
    response = api_client.get("/data")
    return response.json()

def consume_in_audit_context(api_client):
    """Audit-tier consumer uses .get with default on external data."""
    payload = fetch_external(api_client)
    user_id = payload.get("user_id", "anonymous")
    return user_id
