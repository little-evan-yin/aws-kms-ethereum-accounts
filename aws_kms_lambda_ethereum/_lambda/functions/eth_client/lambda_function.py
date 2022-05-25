#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os
from eth_utils import to_hex

from lambda_helper import (assemble_tx,
                           get_tx_params,
                           calc_eth_address,
                           get_kms_public_key,
                           calc_eth_pubkey,
                           sign_kms_raw)

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)


def lambda_handler(event, context):
    _logger.debug("incoming event: {}".format(event))

    operation = event.get('operation')

    if not operation:
        raise ValueError('operation needs to be specified in request and needs to be either "info", "sign" or "sign_raw"')

    response_dict = {"code": 0, "msg": "success", "data": {}}

    # {"operation": "info"}
    if operation == 'info':
        # key_id = os.getenv('KMS_KEY_ID')
        info_body = event.get('info', {})
        key_id = info_body.get('kms_key_id', "0")
        if key_id == "0":
            response_dict['code'] = 100
            response_dict['msg'] = "please input the correct key_id.."
            return response_dict

        pub_key = get_kms_public_key(key_id)
        raw_pub_key = calc_eth_pubkey(pub_key)
        eth_checksum_address = calc_eth_address(pub_key)

        # pub_key to str
        pub_key_str = to_hex(raw_pub_key)

        response_dict['data'] = {'address': eth_checksum_address, "pub_key": pub_key_str}
        return response_dict

    elif operation == 'sign':
        sign_body = event.get('sign', {})

        # get key_id from send request
        key_id = sign_body.get('kms_key_id', "0")
        if key_id == "0":
            response_dict['code'] = 100
            response_dict['msg'] = "please input the correct key_id.."
            return response_dict

        # get destination address from send request
        to_address = sign_body.get('to', "")

        # get amount from send request
        value = sign_body.get('value', "")

        # nonce from send request
        nonce = sign_body.get('nonce', "")

        # data from send request
        data = sign_body.get('data', '0x00')

        # gas
        gas = sign_body.get('gas', "")

        # chainId
        chain_id = sign_body.get('chainId', "0x00")

        # optional params
        # type
        type = int(str(sign_body.get('type', "1")), 16)

        # gasPrice
        gas_price = sign_body.get('gasPrice', "0x00")

        # maxFeePerGas
        max_fee_per_gas = sign_body.get('maxFeePerGas', "0x00")

        # maxPriorityFeePerGas
        max_priority_fee_per_gas = sign_body.get("maxPriorityFeePerGas", "0x00")

        if int(chain_id, 16) < 0:
            response_dict['code'] = 100
            response_dict['msg'] = "error, missing parameter: chain_id"
            return response_dict

        if not (len(value) > 0 and len(nonce) > 0 and len(gas) > 0):
            response_dict['code'] = 100
            response_dict['msg'] = "error, missing parameter: requires value, nonce and gas to be specified"
            return response_dict

        # download public key from KMS
        pub_key = get_kms_public_key(key_id)

        # calculate the Ethereum public address from public key
        eth_checksum_addr = calc_eth_address(pub_key)

        # collect raw parameters for Ethereum transaction
        tx_params = get_tx_params(to_address, value, nonce, data, chain_id, gas, gas_price, type, max_fee_per_gas,
                                  max_priority_fee_per_gas)

        # assemble Ethereum transaction and sign it offline
        raw_tx_signed_hash, raw_tx_signed_payload = assemble_tx(tx_params=tx_params,
                                                                kms_key_id=key_id,
                                                                eth_checksum_addr=eth_checksum_addr,
                                                                chain_id=chain_id,
                                                                type=type)
        response_dict['data'] = {"signed_tx": raw_tx_signed_payload}
        return response_dict

    elif operation == 'sign_raw':
        sign_raw_body = event.get("sign_raw")
        key_id = sign_raw_body.get('kms_key_id', "0")
        if key_id == "0":
            response_dict['code'] = 100
            response_dict['msg'] = "please input the correct key_id.."
            return response_dict
        data = sign_raw_body.get('data', '0x00')

        signature = sign_kms_raw(key_id, data)
        response_dict['data'] = signature
        return response_dict


