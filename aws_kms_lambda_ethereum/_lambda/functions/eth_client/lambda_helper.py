#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import logging
import os
import sys
import time

import asn1tools
import boto3
from botocore.client import Config
from eth_utils import to_hex
from eth_account import Account
from eth_account._utils.signing import (
    encode_transaction, serializable_unsigned_transaction_from_dict)
from web3.auto import w3
from eth_typing import Hash32
from eth_utils.curried import keccak
from eth_account.messages import encode_defunct


session = boto3.session.Session()

handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(lineno)d - %(message)s')
handler.setFormatter(formatter)

_logger = logging.getLogger('app')
_logger.setLevel(os.getenv('LOGGING_LEVEL', 'WARNING'))
_logger.addHandler(handler)

# max value on curve / https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


class EthKmsParams:
    def __init__(self, kms_key_id: str, eth_network: str):
        self._kms_key_id = kms_key_id
        self._eth_network = eth_network

    def get_kms_key_id(self) -> str:
        return self._kms_key_id


def get_params() -> EthKmsParams:
    for param in ['KMS_KEY_ID', 'ETH_NETWORK']:
        value = os.getenv(param)

        if not value:
            if param in ['ETH_NETWORK']:
                continue
            else:
                raise ValueError('missing value for parameter: {}'.format(param))

    return EthKmsParams(
        kms_key_id=os.getenv('KMS_KEY_ID'),
        eth_network=os.getenv('ETH_NETWORK')
    )


def get_kms_public_key(key_id: str) -> bytes:
    # client = session.client('kms')
    start_time = time.time()
    # 需要指定区域、身份信息已加快初始速度吗？？
    config = Config(region_name="ap-northeast-1", connect_timeout=5, max_pool_connections=100,
                    retries={'max_attempts': 10, 'mode': 'standard'})
    client = boto3.client(service_name='kms')
    response = client.get_public_key(
        KeyId=key_id
    )
    end_time = time.time()
    print("get pubkey cost time: {} 's".format(end_time - start_time))

    return response['PublicKey']


def sign_kms(key_id: str, msg_hash: bytes) -> dict:
    # client = session.resource('kms')
    # client = session.client('kms')
    start_time = time.time()
    config = Config(region_name="ap-northeast-1", connect_timeout=5, max_pool_connections=100,
                    retries={'max_attempts': 10, 'mode': 'standard'})
    # 增加endpoint_url指向VPC
    client = boto3.client(service_name='kms')

    response = client.sign(
        KeyId=key_id,
        Message=msg_hash,
        MessageType='DIGEST',
        SigningAlgorithm='ECDSA_SHA_256'
    )
    end_time = time.time()
    print("sign kms cost time: {} 's".format(end_time - start_time))

    return response


def sign_kms_raw(key_id: str, data: str) -> dict:
    pub_key = get_kms_public_key(key_id)
    eth_checksum_address = calc_eth_address(pub_key)

    msghash = encode_defunct(text=data)
    joined = b'\x19' + msghash.version + msghash.header + msghash.body
    message_hash = Hash32(keccak(joined))
    signature = find_eth_signature(key_id, message_hash)

    for v in [27, 28]:
        recovered_addr = Account.recoverHash(message_hash=message_hash,
                                             vrs=(v, signature['r'], signature['s']))
        if recovered_addr == eth_checksum_address:
            return {'r': to_hex(signature['r']), 's': to_hex(signature['s']), 'v': v}

    raise {}


def sign_kms_raw_1559(key_id: str, data: str, chain_id: str) -> dict:
    msghash = encode_defunct(text=data)
    joined = b'\x19' + msghash.version + msghash.header + msghash.body
    message_hash = Hash32(keccak(joined))
    signature = find_eth_signature(key_id, message_hash)

    pub_key = get_kms_public_key(key_id)
    eth_checksum_address = calc_eth_address(pub_key)
    chainid = int(chain_id, 16)
    v_lower = chainid * 2 + 35
    v_range = [v_lower, v_lower + 1]

    for v in v_range:
        recovered_addr = Account.recoverHash(message_hash=message_hash, vrs=(v, signature['r'], signature['s']))

        if recovered_addr == eth_checksum_address:
            return {'r': to_hex(signature['r']), 's': to_hex(signature['s']), 'v': v}

    return {}


def sign_kms_raw_byte(key_id: str, data: bytes, chain_id: str) -> dict:
    signature = find_eth_signature(key_id, data)

    pub_key = get_kms_public_key(key_id)
    eth_checksum_address = calc_eth_address(pub_key)
    chainid = int(chain_id, 16)
    v_lower = chainid * 2 + 35
    v_range = [v_lower, v_lower + 1]

    for v in v_range:
        recovered_addr = Account.recoverHash(message_hash=data, vrs=(v, signature['r'], signature['s']))

        if recovered_addr == eth_checksum_address:
            print("true")
            return {'r': to_hex(signature['r']), 's': to_hex(signature['s']), 'v': v}

    return {}


def calc_eth_pubkey(pub_key) -> str:
    SUBJECT_ASN = '''
    Key DEFINITIONS ::= BEGIN

    SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm         AlgorithmIdentifier,
       subjectPublicKey  BIT STRING
     }

    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
      }

    END
    '''
    key = asn1tools.compile_string(SUBJECT_ASN)
    key_decoded = key.decode('SubjectPublicKeyInfo', pub_key)

    pub_key_raw = key_decoded['subjectPublicKey'][0]
    pub_key = pub_key_raw[1:len(pub_key_raw)]

    return pub_key


def calc_eth_address(pub_key) -> str:
    SUBJECT_ASN = '''
    Key DEFINITIONS ::= BEGIN

    SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm         AlgorithmIdentifier,
       subjectPublicKey  BIT STRING
     }

    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
      }

    END
    '''

    key = asn1tools.compile_string(SUBJECT_ASN)
    key_decoded = key.decode('SubjectPublicKeyInfo', pub_key)

    pub_key_raw = key_decoded['subjectPublicKey'][0]
    pub_key = pub_key_raw[1:len(pub_key_raw)]

    # https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
    hex_address = w3.keccak(bytes(pub_key)).hex()
    eth_address = '0x{}'.format(hex_address[-40:])

    eth_checksum_addr = w3.toChecksumAddress(eth_address)

    return eth_checksum_addr


def find_eth_signature(kms_key_id: str, plaintext: bytes) -> dict:
    SIGNATURE_ASN = '''
    Signature DEFINITIONS ::= BEGIN

    Ecdsa-Sig-Value  ::=  SEQUENCE  {
           r     INTEGER,
           s     INTEGER  }

    END
    '''
    signature_schema = asn1tools.compile_string(SIGNATURE_ASN)

    signature = sign_kms(kms_key_id, plaintext)

    # https://tools.ietf.org/html/rfc3279#section-2.2.3
    signature_decoded = signature_schema.decode('Ecdsa-Sig-Value', signature['Signature'])
    s = signature_decoded['s']
    r = signature_decoded['r']

    secp256_k1_n_half = SECP256_K1_N / 2

    if s > secp256_k1_n_half:
        s = SECP256_K1_N - s

    return {'r': r, 's': s}


def get_recovery_id(msg_hash, r, s, eth_checksum_addr, chain_id) -> dict:
    chainid = int(chain_id, 16)
    v_lower = chainid * 2 + 35
    v_range = [v_lower, v_lower + 1]

    for v in v_range:
        recovered_addr = Account.recoverHash(message_hash=msg_hash, vrs=(v, r, s))

        if recovered_addr == eth_checksum_addr:
            return {"recovered_addr": recovered_addr, 'v': v}

    return {}


def get_tx_params(to_address: str, value: str, nonce: str, data: str, chain_id: str, gas: str,
                  gas_price: str, type: int, max_fee_per_gas: str, max_priority_fee_per_gas: str) -> dict:
    transaction = {
        'nonce': nonce,
        'to': to_address,
        'value': value,
        'data': data,
        'chainId': chain_id,
        'gas': gas
    }

    if len(to_address) > 0:
        transaction['to'] = to_address

    if type > 1:
        # eip1559
        transaction['type'] = type
        transaction['maxFeePerGas'] = max_fee_per_gas
        transaction['maxPriorityFeePerGas'] = max_priority_fee_per_gas
    else:
        transaction['gasPrice'] = gas_price

    return transaction


def assemble_tx(tx_params: dict, kms_key_id: str, eth_checksum_addr: str, chain_id: str, type: int) -> (bytes, bytes):
    tx_unsigned = serializable_unsigned_transaction_from_dict(transaction_dict=tx_params)
    tx_hash = tx_unsigned.hash()

    tx_sig = find_eth_signature(kms_key_id,
                                plaintext=tx_hash)

    tx_eth_recovered_pub_addr = get_recovery_id(msg_hash=tx_hash,
                                                r=tx_sig['r'],
                                                s=tx_sig['s'],
                                                eth_checksum_addr=eth_checksum_addr,
                                                chain_id=chain_id)

    tx_encoded = encode_transaction(unsigned_transaction=tx_unsigned,
                                    vrs=(tx_eth_recovered_pub_addr['v'], tx_sig['r'], tx_sig['s']))

    tx_encoded_hex = w3.toHex(tx_encoded)
    tx_hash = w3.keccak(hexstr=tx_encoded_hex).hex()

    return tx_hash, tx_encoded_hex


if __name__ == "__main__":
    # 测试sign msg
    for i in range(50):
        key_id = "arn:aws:kms:ap-northeast-1:511868236604:key/6bba1312-e8f1-499d-b275-a5757f1fe0ef"
        data = "hellokms" + str(i) + "count"
        sign_kms_raw(key_id, data)
