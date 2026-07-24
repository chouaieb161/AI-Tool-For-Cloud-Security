from __future__ import annotations

import sys, os
sys.path.insert(0, r"C:\Users\MSI\AI-tool-for-cloud-security\backend")

from dotenv import load_dotenv
load_dotenv(r"C:\Users\MSI\AI-tool-for-cloud-security\.env")

from supabase import create_client

url = os.environ["OCI_SUPABASE_URL"]
key = os.environ["OCI_SUPABASE_KEY"]
client = create_client(url, key)

table = os.environ.get("OCI_SUPABASE_VECTORS_TABLE", "oci_vectors")
query_name = os.environ.get("OCI_SUPABASE_QUERY_NAME", "match_documents")

# Test: try the RPC directly
try:
    res = client.rpc(query_name, {"query_embedding": [0.0]*1024, "match_count": 5}).execute()
    print(f"RPC {query_name} OK: {len(res.data)} rows")
    if res.data:
        print("First row keys:", list(res.data[0].keys()))
except Exception as e:
    print(f"RPC {query_name} failed: {e}")
    # Try listing available RPC functions
    try:
        rpcs = client.rpc("pgbouncer_version").execute()
    except:
        pass
    # Try direct table query instead
    try:
        resp = client.table(table).select("id,metadata").limit(3).execute()
        print(f"Direct table query works: {len(resp.data)} rows")
        for r in resp.data:
            print(f"  id={r['id']}, metadata={r.get('metadata', {})}")
    except Exception as e2:
        print(f"Direct query also failed: {e2}")
