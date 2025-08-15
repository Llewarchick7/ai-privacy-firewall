import json
import asyncio
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import SessionLocal, Base, engine
from backend.models.users import Users
from backend.services.auth import hash_password, create_access_token

Base.metadata.create_all(bind=engine)
client = TestClient(app)

@pytest.fixture(scope='module')
def auth_token():
    db = SessionLocal()
    u = db.query(Users).filter(Users.email=='test@example.com').first()
    if not u:
        u = Users(name='Test', email='test@example.com', password_hash=hash_password('password'), role='user', is_verified=True)
        db.add(u)
        db.commit()
        db.refresh(u)
    token = create_access_token({"sub": u.email, "role": u.role})
    db.close()
    return token

def test_batch_ingest_and_stream(auth_token):
    # Open WebSocket
    with client.websocket_connect(f"/api/dns/stream?token={auth_token}") as ws:
        batch = [
            {"device_id":"testdev","query_name":"malware.example.tk","query_type":"A","client_ip":"1.2.3.4","response_code":"NOERROR","response_ip":"5.6.7.8","timestamp": 1723590000},
            {"device_id":"testdev","query_name":"github.com","query_type":"A","client_ip":"1.2.3.4","response_code":"NOERROR","response_ip":"140.82.113.4","timestamp": 1723590001}
        ]
        r = client.post('/api/dns/dns-queries/batch', json=batch, headers={'Authorization': f'Bearer {auth_token}', 'X-Device-Token': ''})
        assert r.status_code == 200, r.text
        # Collect a few events
        received = []
        for _ in range(4):
            try:
                evt = ws.receive_json(timeout=2)
                if evt.get('type')=='dns':
                    received.append(evt)
            except Exception:
                break
        assert any('malware.example.tk' in e.get('domain','') for e in received)
