"""TrustCert - issueCert Lambda (POST /issue)

A university signs a certificate with ITS OWN AWS KMS key.
Only users in the Cognito group "<issuer>-issuer" (for example "msu-issuer")
may issue for that issuer, so no university can issue in another's name.
This function runs with the IAM role TrustCert-Issuer.

Environment variables:
  CERTS_TABLE   = TrustCert-Certificates
  ISSUERS_TABLE = TrustCert-Issuers
"""
import base64
import datetime
import hashlib
import json
import os
import secrets

import boto3

kms = boto3.client("kms")
ddb = boto3.resource("dynamodb")
CERTS = ddb.Table(os.environ.get("CERTS_TABLE", "TrustCert-Certificates"))
ISSUERS = ddb.Table(os.environ.get("ISSUERS_TABLE", "TrustCert-Issuers"))


def canon(obj):
    """Canonical JSON: sorted keys, no spaces. Signer and verifier must use the same rule."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def caller_groups(event):
    """Cognito groups from the API Gateway (HTTP API) JWT authorizer."""
    claims = (event.get("requestContext", {}).get("authorizer", {})
              .get("jwt", {}).get("claims", {}))
    raw = claims.get("cognito:groups", "")
    if isinstance(raw, list):
        return raw
    return [g for g in raw.strip("[]").replace(",", " ").split() if g]


def reply(status, body):
    return {"statusCode": status,
            "headers": {"Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*"},
            "body": json.dumps(body)}


def lambda_handler(event, context):
    data = json.loads(event.get("body") or "{}")
    issuer_id = data.get("issuerId", "")

    # 1. Separation of duties: the caller must be in the issuer's "-issuer" group.
    if f"{issuer_id}-issuer" not in caller_groups(event):
        return reply(403, {"error": f"You are not allowed to issue for '{issuer_id}'."})

    issuer = ISSUERS.get_item(Key={"issuerId": issuer_id}).get("Item")
    if not issuer:
        return reply(404, {"error": f"Unknown issuer '{issuer_id}'."})

    for field in ("name", "studentId", "title", "dateConferred"):
        if not data.get(field):
            return reply(400, {"error": f"Missing field '{field}'."})

    year = data["dateConferred"][:4]
    body = {
        "type": "AcademicCredential",
        "version": 1,
        "certId": f"TC-{year}-{issuer_id.upper()}-{secrets.token_hex(3).upper()}",
        "issuer": {"id": issuer_id, "name": issuer["name"],
                   "keyFingerprint": issuer.get("keyFingerprint", "")},
        "subject": {"name": data["name"].strip(), "studentId": data["studentId"].strip()},
        "credential": {"title": data["title"].strip(),
                       "honors": data.get("honors", "").strip(),
                       "dateConferred": data["dateConferred"]},
        "issuedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    # 2. Sign the SHA-256 digest with the issuer's own asymmetric KMS key.
    #    The private key never leaves KMS.
    digest = hashlib.sha256(canon(body).encode("utf-8")).digest()
    signed = kms.sign(KeyId=issuer["kmsKeyId"], Message=digest,
                      MessageType="DIGEST", SigningAlgorithm="ECDSA_SHA_256")
    cert = dict(body, signature={"alg": "ECDSA_SHA_256", "curve": "P-256",
                                 "value": base64.b64encode(signed["Signature"]).decode()})

    # 3. The issuer keeps its own record (used later for revocation checks).
    CERTS.put_item(Item={"certId": cert["certId"], "issuerId": issuer_id,
                         "status": "VALID", "certificate": json.dumps(cert)})
    return reply(201, cert)
