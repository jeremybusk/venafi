#!/usr/bin/python3
# ./vcli.py  -H venafi.example.com -c <api-client-id> -u <myuser> -d "\VED\Policy\Certificates\Common\Development\*.dev.example.com"

import argparse
import base64
import os
from pprint import pprint
import requests


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r


class EnvDefault(argparse.Action):
    def __init__(self, envvar, required=True, default=None, **kwargs):
        if not default and envvar:
            if envvar in os.environ:
                default = os.environ[envvar]
        if required and default:
            required = False
        super(EnvDefault, self).__init__(default=default, required=required,
                                         **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)


parser = argparse.ArgumentParser(
    description='Create Zabbix screen from all of a host Items or Graphs.')
parser.add_argument('-H', '--api-host', required=True, type=str,
                    default=os.environ.get('API_HOST'),
                    help='API host fqdn.')
parser.add_argument('-c', '--client_id', required=True, type=str,
                    default=os.environ.get('CLIENT_ID'),
                    help='API Integration Name/Client ID.')
parser.add_argument('-u', '--username', required=True, type=str,
                    default=os.environ.get('USERNAME'),
                    help='API Username.')
parser.add_argument('-p', '--password', required=True, type=str,
                    action=EnvDefault, envvar='PASSWORD',
                    help='API password.')
parser.add_argument('-s', '--scope', required=False, type=str,
                    default="certificate:manage",
                    help='API password.')
parser.add_argument('-d', '--cert-dn', required=True, type=str,
                    help='Certificate folder file path.')
parser.add_argument('-v', '--verbose',
                    action='store_true')  # on/off flag
args = parser.parse_args()


def get_auth_token():
    auth_json = {
        "client_id": args.client_id,
        "username": args.username,
        "password": args.password,
        "scope": args.scope
    }
    url = f'https://{args.api_host}/vedauth/authorize/oauth'
    rsp = requests.post(url, json=auth_json)
    token = rsp.json()['access_token']
    return token


def get_crt_via_guid(token, cert_guid):
    url = f"https://{args.api_host}/vedsdk/certificates/{{guid}}"
    rsp = requests.get(url, auth=BearerAuth(token))
    pprint(rsp.json())
    return rsp.json()


def search_crt(token, limit, offset=0):
    url1 = f"https://{args.api_host}/vedsdk/certificates/"
    url2 = f"?parentdnrecursive=%5CVED%5CPolicy&limit={limit}&offset={offset}"
    url = f"{url1}{url2}"
    rsp = requests.get(url, auth=BearerAuth(token))
    pprint(rsp.json())
    return rsp.json()


def get_crt_via_dn(token, cert_dn):
    cert_dn = cert_dn.replace("\\", "\\\\")
    dn_json = {
        "CertificateDN": cert_dn,
        "Format": "Base64",
        "IncludeChain": "true",
        "RootFirstOrder": "true"
    }
    headers = {}
    headers["authorization"] = "Bearer " + token
    url = f"https://{args.api_host}/vedsdk/Certificates/Retrieve"
    rsp = requests.post(url, json=dn_json, auth=BearerAuth(token))
    crt_pem = base64.b64decode(rsp.json()['CertificateData'])
    return crt_pem.decode('utf-8')


def main():
    token = get_auth_token()
    # search_crt(token, 2)
    cert_pem = get_crt_via_dn(token, args.cert_dn)
    print(cert_pem)


if __name__ == '__main__':
    main()
