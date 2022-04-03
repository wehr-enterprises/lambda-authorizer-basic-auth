"""
   Copyright 2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.

   Licensed under the MIT License. See the LICENSE accompanying this file
   for the specific language governing permissions and limitations under
   the License.
"""
import os
import re
import json
import logging
import base64

import boto3

# from aws_xray_sdk.core import xray_recorder
# from aws_xray_sdk.core import patch_all
# patch_all()

# Static code used for DynamoDB connection and logging
dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
table = dynamodb.Table(
    os.environ.get("TABLE_NAME", "lambda-authorizer-basic-auth-users")
)
log_level = os.environ.get("LOG_LEVEL", "DEBUG")
log = logging.getLogger(__name__)
logging.getLogger().setLevel(log_level)

ERR_401_MISSING = {
    "status": "401",
    "headers": {
        "www-authenticate": [
            {"key": "WWW-Authenticate", "value": 'Basic realm="auth required"'}
        ],
        "edge-auth-error": [
            {"key": "Edge-Auth-Error", "value": "missing authorization header"}
        ],
    },
}

ERR_401_INVALID = {
    "status": "400",
    "headers": {
        "edge-auth-error": [
            {"key": "Edge-Auth-Error", "value": "invalid authorization header"}
        ]
    },
}

ERR_403_SHH = {
    "status": "404",
    "headers": {
        "edge-auth-error": [{"key": "Edge-Auth-Error", "value": "nobody home"}]
    },
}


def lambda_handler(event, context):

    try:
        request = event["Records"][0]["cf"]["request"]
        headers = request.get("headers", {})
        print("headers: " + json.dumps(headers))

        auth_header = headers.get("authorization", [{}])[0].get("value")
        if auth_header is None or not str(auth_header).lower().strip().startswith(
            "basic"
        ):
            return ERR_401_MISSING

        auth_encoded = auth_header.strip().split()[1]
        log.debug("auth_encoded: " + auth_encoded)

        auth = base64.b64decode(auth_encoded.encode("utf-8")).decode("utf-8")
        if not ":" in auth:
            return ERR_401_INVALID

        username, token = auth.split(":", maxsplit=1)
        log.debug("username: " + username)

        # Get the password from DynamoDB for the username
        item = table.get_item(ConsistentRead=True, Key={"username": username})
        if item.get("Item") is not None:
            log.debug("item: " + json.dumps(item))
            ddb_password = item.get("Item").get("password")
            log.debug("ddb_password:" + json.dumps(ddb_password))

            if ddb_password is not None:
                ddb_username_password = username + ":" + ddb_password
                ddb_username_password_hash = base64.b64encode(
                    ddb_username_password.encode()
                ).decode()
                log.debug("ddb_username_password_hash:" + ddb_username_password_hash)
                if str(auth_encoded) == str(ddb_username_password_hash):
                    log.info("password ok for: " + username)
                    return request
                else:
                    log.info("password does not match for: " + username)
                    return ERR_403_SHH
            else:
                log.info("No password found for username:" + username)
                raise Exception("USER")
        else:
            log.info("No username:" + username)
            raise Exception("user")

    except Exception as exc:
        return _make_err_500(f"oh no: {exc}")


def _make_err_500(msg: str) -> dict:
    return {
        "status": "500",
        "headers": {"edge-auth-error": [{"key": "Edge-Auth-Error", "value": msg}]},
    }
