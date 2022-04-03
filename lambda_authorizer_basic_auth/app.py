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
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ.get('TABLE_NAME', 'lambda-authorizer-basic-auth-users'))
log_level = os.environ.get('LOG_LEVEL', 'INFO')
log = logging.getLogger(__name__)
logging.getLogger().setLevel(log_level)


def lambda_handler(event, context):
    request = event['Records'][0]['cf']['request']
    headers = request['headers']
    response = event['Records'][0]['cf']['response']
    print("headers: " + json.dumps(headers))

    try:

        # Get authorization header in lowercase
        authorization_header = {k.lower(): v for k, v in headers.items() if k.lower() == 'authorization'}
        log.debug("authorization: " + json.dumps(authorization_header))

        # Get the username:password hash from the authorization header
        username_password_hash = authorization_header['authorization'].split()[1]
        log.debug("username_password_hash: " + username_password_hash)

        # Decode username_password_hash and get username
        username = base64.standard_b64decode(username_password_hash).split(':')[0]
        log.debug("username: " + username)

        # Get the password from DynamoDB for the username
        item = table.get_item(ConsistentRead=True, Key={"username": username})
        if item.get('Item') is not None:
            log.debug("item: " + json.dumps(item))
            ddb_password = item.get('Item').get('password')
            log.debug("ddb_password:" + json.dumps(ddb_password))

            if ddb_password is not None:
                ddb_username_password = (username + ":" + ddb_password)
                ddb_username_password_hash = base64.standard_b64encode(ddb_username_password)
                log.debug("ddb_username_password_hash:" + ddb_username_password_hash)
                if username_password_hash == ddb_username_password_hash:
                    pass
                    log.info("password ok for: " + username)
                else:
                    raise Exception('Unauthorized - 2480')
                    log.info("password does not match for: " + username)
            else:
                raise Exception('Unauthorized - 2364')
                log.info("No password found for username:" + username)
        else:
            raise Exception('Unauthorized - 2364')

        return response
    except Exception:
        raise Exception('Unauthorized')
