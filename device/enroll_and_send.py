#!/usr/bin/env python3
"""Raspberry Pi (or dev host) enrollment + sample DNS batch sender.
Usage:
  python enroll_and_send.py --server http://localhost:8000 --code ABC123XYZ --mac B8:27:EB:12:34:56 --hostname pi-firewall
This will:
  1. Complete enrollment with code to obtain device_secret.
  2. Send a signed sample DNS batch using HMAC headers.
"""
import argparse, json, os, time, hmac, hashlib, requests, sys
from pathlib import Path

STORE = Path.home() / '.aifirewall'
CREDS = STORE / 'device_credentials.json'

def save_creds(data):
    STORE.mkdir(parents=True, exist_ok=True)
    CREDS.write_text(json.dumps(data, indent=2))

def load_creds():
    if CREDS.exists():
        return json.loads(CREDS.read_text())
    return None

def complete_enrollment(server, code, mac, hostname):
    r = requests.post(f"{server}/api/dns/devices/complete-enrollment", json={
        "enrollment_code": code.strip(),
        "mac_address": mac.strip(),
        "hostname": hostname
    })
    if r.status_code != 200:
        print("Enrollment failed:", r.status_code, r.text, file=sys.stderr)
        sys.exit(1)
    data = r.json()
    save_creds(data)
    print("Enrollment success. Credentials stored at", CREDS)
    return data

def sign_and_send(server, creds):
    device_id = creds['device_uuid']
    secret = creds['device_secret']
    ts = int(time.time())
    batch = [
        {"device_id": device_id, "query_name": "example.com", "query_type": "A", "client_ip": "192.168.1.10", "response_code": "NOERROR", "response_ip": "93.184.216.34", "timestamp": ts},
        {"device_id": device_id, "query_name": "suspicious.phish.tk", "query_type": "A", "client_ip": "192.168.1.10", "response_code": "NOERROR", "response_ip": "10.10.10.10", "timestamp": ts}
    ]
    body = json.dumps(batch, separators=(',', ':')).encode()
    sig = hmac.new(secret.encode(), body + b'.' + str(ts).encode(), hashlib.sha256).hexdigest()
    r = requests.post(f"{server}/api/dns/dns-queries/batch", data=body, headers={
        'Content-Type': 'application/json',
        'X-Device-Id': device_id,
        'X-Timestamp': str(ts),
        'X-Signature': sig
    })
    print('Batch status', r.status_code, r.text)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--server', default='http://localhost:8000')
    p.add_argument('--code', help='Enrollment code (one-time)')
    p.add_argument('--mac', help='Device MAC (or unique id)')
    p.add_argument('--hostname', default='pi-firewall')
    p.add_argument('--send-only', action='store_true', help='Use existing creds; just send batch')
    args = p.parse_args()

    creds = load_creds()
    if args.send_only:
        if not creds:
            print('No stored creds. Run without --send-only first.', file=sys.stderr)
            sys.exit(1)
    else:
        if not (args.code and args.mac):
            print('Enrollment requires --code and --mac', file=sys.stderr)
            sys.exit(1)
        creds = complete_enrollment(args.server, args.code, args.mac, args.hostname)

    sign_and_send(args.server, creds)

if __name__ == '__main__':
    main()
