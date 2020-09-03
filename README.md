# nxtool

A command line tool to easily sync Nexpose scan engines to their consoles. 

Nexpose is iCIMS vulnerability management solution. Scan engines are deployed throughout our organization to manage scanning assets for vulnerabilities. These engines then report back to a main hub called the console. This script is designed to help pair scan engines to their consoles without much human intervention. 

## Installation

1. Install python3.5 or greater
2. Clone this repo
3. run `python3 setup.py install`


## Usage

```python
nxtool --help
usage: nxtool [-h] [-k PRIVATE_KEY] -u NXUSERNAME -p NXPASSWORD
              [-o {xml,json,string}] [-l] [-e ENGINE_USER] [-s ENGINE_SERVER]

optional arguments:
  -h, --help            show this help message and exit

required arguments:
  -u NXUSERNAME, --nxusername NXUSERNAME
                        username for your nxadmin account
  -p NXPASSWORD, --nxpassword NXPASSWORD
                        password for your nxadmin account

optional arguments:
  -k PRIVATE_KEY, --private_key PRIVATE_KEY
                        ssh private key path for auth to nexpose scan engine
  -o {xml,json,string}, --output {xml,json,string}
                        output types [xml, json, string]
  -l, --upload          upload xml to azure scan engine
  -e ENGINE_USER, --engine_user ENGINE_USER
                        username for nexpose scan engine server
  -s ENGINE_SERVER, --engine_server ENGINE_SERVER
                        nexpose scan engine server hostname or ip

```

## Examples

To obtain a nexpose console pairing key sent to your console as a string:
```python
nxtool -u {svc_nexpose_console_account} -p {svc_nexpose_console_password} -o string
$ JDJA-DIFS-D2-FDSFS-GFDGDFGDF-FGSD-FSDF
```

You can also out to your console in JSON (default) and a special XML format for Azure scan engines.

To obtain a console pairing key and upload the key to an Azure scan engine automatically:
```python
nxtool -u {svc_nexpose_console_account} -p {svc_nexpose_console_password} -k /.ssh/azure_pk.pem -e {nexpose_engine_account} -s {nexpose_engine_server_host_or_ip} --upload
```


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.
