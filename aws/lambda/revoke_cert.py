"""TrustCert - revokeCert Lambda (POST /revoke)

Only the Issuer role of the university that issued a certificate can revoke it.
Caller must be in the Cognito group "<issuer>-issuer". Runs with IAM role TrustCert-Issuer.
Request body: {"certId": "TC-2026-MSU-1A2B3C"}
"""
import json
import os

import boto3
from botocore.exceptions import ClientError

ddb = boto3.resource("dynamodb")
CERTS = ddb.Table(os.environ.get("CERTS_TABLE", "TrustCert-Certificates"))


def caller_groups(event):
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
    cert_id = json.loads(event.get("body") or "{}").get("certId", "")
    groups = caller_groups(event)
    record = CERTS.get_item(Key={"certId": cert_id}).get("Item")
    if not record:
        return reply(404, {"error": "Certificate not found."})
    if f"{record['issuerId']}-issuer" not in groups:
        return reply(403, {"error": "Only the issuing university can revoke this certificate."})
    try:
        CERTS.update_item(Key={"certId": cert_id},
                          UpdateExpression="SET #s = :r",
                          ConditionExpression="issuerId = :i",
                          ExpressionAttributeNames={"#s": "status"},
                          ExpressionAttributeValues={":r": "REVOKED", ":i": record["issuerId"]})
    except ClientError as err:
        return reply(409, {"error": str(err)})
    return reply(200, {"certId": cert_id, "status": "REVOKED"})
