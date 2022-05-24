#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os

from lambda_helper import (assemble_tx,
                           get_params,
                           get_tx_params,
                           calc_eth_address,
                           get_kms_public_key,
                           sign_kms_raw)

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)


def lambda_handler(event, context):
    _logger.debug("incoming event: {}".format(event))

    try:
        params = get_params()
    except Exception as e:
        raise e

    operation = event.get('operation')
    if not operation:
        raise ValueError('operation needs to be specified in request and needs to be eigher "status" or "send"')

    # {"operation": "status"}
    if operation == 'status':
        # key_id = os.getenv('KMS_KEY_ID')
        key_id = event.get('kms_key_id', "0")
        if key_id == "0":
            key_id = os.getenv('KMS_KEY_ID')

        pub_key = get_kms_public_key(key_id)
        eth_checksum_address = calc_eth_address(pub_key)

        return {'eth_checksum_address': eth_checksum_address}

    elif operation == 'sign':
        # get key_id from environment varaible
        # key_id = os.getenv('KMS_KEY_ID')
        # get key_id from send request
        key_id = event.get('kms_key_id', "0")
        if key_id == "0":
            key_id = os.getenv('KMS_KEY_ID')

        # get destination address from send request
        to_address = event.get('to', "")      # 16进制字符串

        # get amount from send request
        value = event.get('value', "")

        # nonce from send request
        nonce = event.get('nonce', "")

        # data from send request
        data = event.get('data', '0x00')

        # gas
        gas = event.get('gas', "")

        # chainId
        chain_id = event.get('chainId', "0x00")

        # optional params
        # type
        type = event.get('type', -1)

        # gasPrice
        gas_price = event.get('gasPrice', "0x00")

        # maxFeePerGas
        max_fee_per_gas = event.get('maxFeePerGas', "0x00")

        # maxPriorityFeePerGas
        max_priority_fee_per_gas = event.get("maxPriorityFeePerGas", "0x00")

        if not (len(to_address) > 0 and len(value) > 0 and len(nonce) > 0 and len(gas) > 0):
            return {'operation': 'sign',
                    'error': 'missing parameter - sign requires value, to_address, nonce and gas to be specified'}

        # download public key from KMS
        pub_key = get_kms_public_key(key_id)

        # calculate the Ethereum public address from public key
        eth_checksum_addr = calc_eth_address(pub_key)

        # collect raw parameters for Ethereum transaction
        tx_params = get_tx_params(to_address, value, nonce, data, chain_id, gas, gas_price, type,
                                  max_fee_per_gas, max_priority_fee_per_gas)

        # assemble Ethereum transaction and sign it offline
        raw_tx_signed_hash, raw_tx_signed_payload = assemble_tx(tx_params=tx_params,
                                                                params=params,
                                                                eth_checksum_addr=eth_checksum_addr,
                                                                chain_id=chain_id,
                                                                type=type)

        return {"signed_tx_hash": raw_tx_signed_hash,
                "signed_tx_payload": raw_tx_signed_payload}

    elif operation == 'sign_raw':
        # key_id = os.getenv('KMS_KEY_ID')
        key_id = event.get('kms_key_id', "0")
        if key_id == "0":
            key_id = os.getenv('KMS_KEY_ID')
        # construct data
        data = event.get('data', '0x00')

        # download public key from KMS
        pub_key = get_kms_public_key(key_id)

        # calculate the Ethereum public address from public key
        eth_checksum_addr = calc_eth_address(pub_key)
        tx_sig = sign_kms_raw(key_id, data, eth_checksum_addr)

        return tx_sig

