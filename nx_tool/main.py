import requests
import os
import json
import logging
import tempfile
import argparse
import paramiko
import tempfile
import shutil
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)

BASE_URL = os.environ.get(
    'BASE_URL', 
    '')

SECRET_TTL_PATH = os.environ.get(
    'SECRET_TTL_PATH', 
    'scan_engines/shared_secret/time_to_live')

SECRET_CREATION_PATH = os.environ.get(
    'SECRET_CREATION_PATH',
    'scan_engines/shared_secret')

NEXPOSE_HOST = os.environ.get(
    'NEXPOSE_HOST',
    '')

NEXPOSE_PORT = os.environ.get(
    'NEXPOSE_PORT',
    '40815')

AZURE_LOCATION = os.environ.get(
    'AZURE_LOCATION',
    '/opt/rapid7/nexpose/nse/conf')

SECRET_TTL_URL = BASE_URL + SECRET_TTL_PATH

SECRET_CREATION_URL = BASE_URL + SECRET_CREATION_PATH

nxusername = ''

nxpassword = ''

scan_engine_private_key = ''

output_type = ''

upload = False

scan_engine_user = ''

scan_engine_server = ''

def main():
    init_cli_args()

    shared_secret = create_shared_secret()

    ttl = get_ttl_of_secret() # ttl is in minutes

    if ttl < 15:
        revoke_shared_secret()
        shared_secret = create_shared_secret()

    if upload:
        upload_data(shared_secret)

    if output_type == 'json':
        data = {
            "status": 200,
            "message": {"sharedSecret": shared_secret}
        }
        return json.dumps(data, indent=4)
    elif output_type == 'xml':
        data = format_in_xml(shared_secret)
        return data
    elif output_type == 'string':
        return shared_secret
    else:
        return {'status': 500, 'message': 'system error'}


def init_cli_args():
    global nxusername
    global nxpassword
    global output_type
    global scan_engine_private_key
    global upload
    global scan_engine_user
    global scan_engine_server

    parser = argparse.ArgumentParser()

    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')

    optional.add_argument(
        "-k", 
        "--private_key", 
        help="ssh private key path for auth to nexpose scan engine")

    required.add_argument(
        "-u", 
        "--nxusername", 
        help="username for your nxadmin account", 
        required=True)

    required.add_argument(
        "-p", 
        "--nxpassword", 
        help="password for your nxadmin account", 
        required=True)

    optional.add_argument(
        "-o", 
        "--output", 
        help="output types [xml, json, string]",
        choices=['xml', 'json', 'string'],
        default='json')

    optional.add_argument(
        "-l", 
        "--upload", 
        help="upload xml to azure scan engine",
        action='store_true')

    optional.add_argument(
        "-e", 
        "--engine_user", 
        help="username for nexpose scan engine server")

    optional.add_argument(
        "-s", 
        "--engine_server", 
        help="nexpose scan engine server hostname or ip")

    cli_args = parser.parse_args()

    nxusername = cli_args.nxusername
    nxpassword = cli_args.nxpassword
    scan_engine_private_key = cli_args.private_key
    output_type = cli_args.output
    upload = cli_args.upload
    scan_engine_user = cli_args.engine_user
    scan_engine_server = cli_args.engine_server


def create_shared_secret():
    response = requests.post(
        url=SECRET_CREATION_URL, 
        auth=HTTPBasicAuth(nxusername, nxpassword))

    if response.status_code == 415:
        raise SystemExit(json.dumps(
            {'status': response.status_code, "message": "unknown error"}, indent=4))
    elif response.status_code != 201:
        raise SystemExit(json.dumps(response.json(), indent=4))

    shared_secret = response.content.decode("utf-8") 

    return shared_secret


def get_ttl_of_secret():
    response = requests.get(
        url=SECRET_TTL_URL, 
        auth=HTTPBasicAuth(nxusername, nxpassword))

    if response.status_code == 415:
        raise SystemExit(json.dumps(
            {'status': response.status_code, "message": "unknown error"}, indent=4))
    elif response.status_code != 200:
        raise SystemExit(json.dumps(response.json(), indent=4))

    ttl = int(response.content)

    return ttl // 60


def revoke_shared_secret():
    response = requests.delete(
        url=SECRET_CREATION_URL, 
        auth=HTTPBasicAuth(nxusername, nxpassword))

    if response.status_code == 415:
        raise SystemExit(json.dumps(
            {'status': response.status_code, "message": "unknown error"}, indent=4))
    elif response.status_code != 200:
        raise SystemExit(json.dumps(response.json(), indent=4))

    return True

def format_in_xml(shared_secret):
    xml = """<?xml version='1.0' encoding='utf-8'?>
    <Consoles>
    <console id="1" enabled="1" connectTo="1" name="UNAVAILABLE" lastAddress="{}" port="{}" plaintext_sharedSecret="{}">
        <cert></cert>
    </console>
    </Consoles>""".format(NEXPOSE_HOST, NEXPOSE_PORT, shared_secret)

    return xml


def upload_data(shared_secret):
    xml = format_in_xml(shared_secret)

    try:
        fd,tmpfile = tempfile.mkstemp()
        file_ = os.fdopen(fd, "w+b")
        file_.write(xml.encode('utf-8'))
        file_.seek(0)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        k = paramiko.RSAKey.from_private_key_file(scan_engine_private_key)
        ssh.connect(scan_engine_server, username=scan_engine_user, pkey = k)
        sftp = ssh.open_sftp()
        sftp.chdir(AZURE_LOCATION)
        sftp.putfo(file_, 'consoles.xml')
    except Exception as e:
        if os.path.exists(tmpfile):
            os.unlink(tmpfile)
  
        data = {
            "status": 500,
            "message": "unable to upload data to {}. {}".format(
                scan_engine_server, str(e))
        }
        
        raise SystemExit(json.dumps(data, indent=4))
    finally:
        if os.path.exists(tmpfile):
            os.unlink(tmpfile)

    data = {
        "status": 200,
        "message": "Data uploaded to {}".format(scan_engine_server)
    }
    raise SystemExit(json.dumps(data, indent=4))


if __name__ == '__main__':
    print(main())
