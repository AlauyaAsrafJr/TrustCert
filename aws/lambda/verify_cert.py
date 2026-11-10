"""TrustCert - verifyCert Lambda (POST /verify)

Another university checks a certificate it received:
  1. Is the issuer known, and does the key fingerprint match?
  2. Does the signature match the contents? (KMS Verify with the issuer's key)
  3. Has the issuer revoked it?
  4. Does the VERIFIER trust the issuer, directly or through one university it trusts?

Request body: {"verifierId": "nsu", "certificate": { ...signed certificate... }}
"""
import base64
import hashlib
import json
import os

import boto3

kms = boto3.client("kms")
ddb = boto3.resource("dynamodb")
CERTS = ddb.Table(os.environ.get("CERTS_TABLE", "TrustCert-Certificates"))
ISSUERS = ddb.Table(os.environ.get("ISSUERS_TABLE", "TrustCert-Issuers"))


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def reply(status, body):
    return {"statusCode": status,
            "headers": {"Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*"},
            "body": json.dumps(body)}


def get_issuer(issuer_id):
    return ISSUERS.get_item(Key={"issuerId": issuer_id}).get("Item")


def trust_path(verifier, issuer_id):
    if verifier["issuerId"] == issuer_id:
        return ["self", [issuer_id]]
    trusts = list(verifier.get("trusts", []))
    if issuer_id in trusts:
        return ["direct", [verifier["issuerId"], issuer_id]]
    for middle_id in trusts:  # one step of delegation
        middle = get_issuer(middle_id)
        if middle and issuer_id in middle.get("trusts", []):
            return ["delegated", [verifier["issuerId"], middle_id, issuer_id]]
    return ["none", []]


def lambda_handler(event, context):
    data = json.loads(event.get("body") or "{}")
    cert = data.get("certificate") or {}
    verifier = get_issuer(data.get("verifierId", ""))
    checks = []

    if not verifier:
        return reply(400, {"error": "Unknown verifierId."})
    if not (cert.get("certId") and cert.get("issuer", {}).get("id") and cert.get("signature", {}).get("value")):
        return reply(200, {"verdict": "invalid", "checks": ["Certificate is missing required parts."]})

    issuer = get_issuer(cert["issuer"]["id"])
    if not issuer or cert["issuer"].get("keyFingerprint") != issuer.get("keyFingerprint", ""):
        return reply(200, {"verdict": "invalid", "checks": ["Issuer or issuer key not recognized."]})
    checks.append(f"Issuer key found for {issuer['name']}.")

    body = {k: v for k, v in cert.items() if k != "signature"}
    digest = hashlib.sha256(canon(body).encode("utf-8")).digest()
    try:
        valid = kms.verify(KeyId=issuer["kmsKeyId"], Message=digest, MessageType="DIGEST",
                           Signature=base64.b64decode(cert["signature"]["value"]),
                           SigningAlgorithm="ECDSA_SHA_256")["SignatureValid"]
    except kms.exceptions.KMSInvalidSignatureException:
        valid = False
    if not valid:
        checks.append("Signature does not match: the certificate was changed or forged.")
        return reply(200, {"verdict": "invalid", "checks": checks})
    checks.append("Signature matches.")

    record = CERTS.get_item(Key={"certId": cert["certId"]}).get("Item")
    if record and record.get("status") == "REVOKED":
        checks.append("Revoked by the issuer.")
        return reply(200, {"verdict": "revoked", "checks": checks})
    checks.append("Not revoked.")

    kind, path = trust_path(verifier, issuer["issuerId"])
    if kind == "none":
        checks.append(f"{verifier['issuerId'].upper()} does not trust {issuer['issuerId'].upper()}.")
        return reply(200, {"verdict": "untrusted", "checks": checks})
    checks.append(f"Trusted ({kind}): " + " -> ".join(p.upper() for p in path))
    return reply(200, {"verdict": "verified", "checks": checks, "trustPath": path})
