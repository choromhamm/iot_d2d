#-*- coding:utf-8 -*-
import sys
import socket
import ssl
import json
import base64
from datetime import datetime as dt, timedelta as td
from hashlib import sha512
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils, rsa

userPubkeyDict = {'user1':'user1_public_key'}
userPermissions = {'user1':'device1/read_data'}

def deserializeMessage(msg):
    # msgDic = []
    # msgDic['user_id'] = 'user1'
    # msgDic['user_public_key'] = 'user1_public_key'
    # msgDic['device_id'] = 'device1'
    # msgDic['requested_permission'] = 'read_data'
    # msgDic['user_signature'] = 'user1_signature'
    msgDic = json.loads(msg)
    return msgDic

def authenticateUser(user_id, user_public_key):
    if user_id in userPubkeyDict:
        return True
        return userPubkeyDict.get(user_id, '') == user_public_key
    return False

def verifySignature(msgDic):
    # public_key = user_public_key
    # 
    signature = base64.b64decode(bytes(msgDic['user_signature'], 'utf-8'))
    public_key = bytes(msgDic['user_public_key'], 'utf-8')

    public_key = serialization.load_pem_public_key(public_key)
    if isinstance(public_key, rsa.RSAPublicKey) == False:
        print('[verifySignature] Invalid User Public Key')
        return False

    result = False
    keys = ['user_id', 'user_public_key', 'device_id', 'requested_permission', 'request_time', 'session_validity']
    try:
        msg = ''
        for key in keys: msg += msgDic[key]
        #print(len(msg))
        
        msg = bytes(msg, 'utf-8')

        result = public_key.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        print('[verifySignature] data is too long: use prehash')
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)

        for key in keys: hasher.update(bytes(msgDic[key], 'utf-8'))
        digest = hasher.finalize()
        
        result = public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(chosen_hash)
        )
    return True


def authorizePermission(user_id, device_id, requested_permission):
    if user_id in userPermissions:
        return userPermissions.get(user_id, '') == f'{device_id}/{requested_permission}'
    return False


def signMessage(msgDic, private_key):
    # TODO: hash and sign msg
    keys = ['user_id', 'user_public_key', 'device_id', 'requested_permission', 'user_signature', 
    'request_time', 'token_valid_until', 'session_validity']

    
    try:
        msg = ''
        for key in keys: msg += msgDic[key]
        msg = bytes(msg, 'utf-8')
    
        signature = private_key.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        print('[signMessage]data is too long: use prehash')

        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        
        for key in keys: hasher.update(bytes(msgDic[key], 'utf-8'))
        digest = hasher.finalize()
        
        signature = private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(chosen_hash)
        )
    signature_str = base64.b64encode(signature).decode('utf8')
    #signature = signature.decode('utf-8')
    return signature_str


def addTokenValidTime(msgDic):
    created_at = dt.strptime(msgDic['request_time'], '%Y-%m-%d %H:%M:%S')
    token_valid_until = created_at + td(minutes=5)
    msgDic['token_valid_until'] = token_valid_until.strftime("%Y-%m-%d %H:%M:%S")
    return msgDic


def serializeMessage(msgDic):
    return json.dumps(msgDic)

def processMessage(msg, private_key):
    msgDic = deserializeMessage(msg)
    #print(msgDic)
    response = ''
    if authenticateUser(msgDic['user_id'], msgDic['user_public_key']) == False:
        response = 'fail to authenticate user'
        print(response)
        return response

    if verifySignature(msgDic) == False:
        response = 'fail to verify signature'
        print(response)
        return response

    if authorizePermission(msgDic['user_id'], msgDic['device_id'], msgDic['requested_permission']) == False: 
        response = 'fail to autorize permission'
        print(response)
        return response

    msgDic = addTokenValidTime(msgDic)
    server_signature = signMessage(msgDic, private_key)
    msgDic['server_signature'] = server_signature
    response = serializeMessage(msgDic)

    return response


def run(ip_addr, port, port2, keyfile, certfile):
    buf_size = 4096
    context = ssl.SSLContext() 

    with open(keyfile, "rb") as fin:
        private_key = serialization.load_pem_private_key(
            fin.read(),
            password=None,
        )

    if isinstance(private_key, rsa.RSAPrivateKey) == False:
        print('[run] Invalid Server Private Key')
        return False
    # context.verify_mode = ssl.CERT_OPTIONAL 
    # context.check_hostname = False
    # context.load_verify_locations(cafile='/path/to/your/cacert.pem')
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock2 = ssl.wrap_socket(
            sock2, server_side=True, ca_certs=certfile, cert_reqs=ssl.CERT_REQUIRED, keyfile=keyfile, certfile=certfile
            )
    sock2.bind((ip_addr, port2))
    sock2.listen(5)
    sock2.setblocking(True);
    print("bind iot port")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock = ssl.wrap_socket(
            sock, server_side=True, keyfile=keyfile, certfile=certfile
        )
        sock.bind((ip_addr, port))
        sock.listen(5)

        sock.setblocking(True);

        iot_conn, addr = sock2.accept()

        iot_conn.setblocking(True);
        print("iot connection established: is blocking? {}".format(iot_conn.getblocking()))
        if iot_conn.fileno() == -1: 
            print("iot connection fail")
            exit()

        iot_conn.sendall(bytes("OK", encoding='utf8'))

        print("iot connection OK sent")
        
        while True:
            print('wait exp')
            client_conn, addr = sock.accept()
            print('start exp')
            client_conn.setblocking(True);
            if client_conn.fileno() == -1: 
                print("client connection fail")
                exit()
            if client_conn.fileno() == -1: continue
            client_msg = client_conn.recv(buf_size)

            if client_conn.fileno() == -1: continue
            #client_conn.sendall(bytes("OK", encoding='utf8'))
            token = processMessage(client_msg, private_key)           
            client_conn.sendall(bytes(token, encoding='utf8'))
            
            if client_conn.fileno() == -1: break
            client_token = client_conn.recv(buf_size)
            token_msg = deserializeMessage(client_token)
            if verifySignature(token_msg) == False:
                response = 'failure'
            response = 'success'
            client_conn.sendall(bytes(response, encoding='utf8'))
            print(response)
            client_cmd = client_conn.recv(buf_size)
            if client_msg.decode(encoding='utf8') == 'q':
                print('end exp')
                break
            client_command = json.loads(client_cmd.decode(encoding='utf8'))
            print("client comnand ::: ", client_command)
                

            cnt = int(client_command["totalDataSize"] / client_command["packetSize"])
            print("count", cnt)
            if iot_conn.fileno() == -1: break
            iot_conn.sendall(bytes(json.dumps(client_command), encoding='utf8'))

            #while True:    
                #if iot_conn.fileno() == -1: break
                #iot_conn.sendall(bytes(json.dumps(client_command), encoding='utf8'))
                #print("delay: {}".format(client_command["delay"]))
                # print("client msg forwarded to iot: {}".format(client_msg))
                 
            while cnt > 0:
                if iot_conn.fileno() == -1: break
                iot_msg = iot_conn.recv(buf_size)
                    # print("iot msg recved: {}".format(iot_msg))
                if client_conn.fileno() == -1: break
                client_conn.sendall(iot_msg)
                    # print("iot msg forwarded to client: {}".format(iot_msg))
                cnt -= 1
        client_conn.close()
        iot_conn.close()
    sock.close()
    sock2.close()


if __name__ == '__main__':
    ip_addr = '0.0.0.0'
    port = 11224
    port2 = 11225
    keyfile = '../server_cert/domain_no_pw.key'
    certfile = '../server_cert/domain.crt'
    run(ip_addr, port, port2, keyfile, certfile)



