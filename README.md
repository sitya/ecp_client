# ecp_client
It is a very simple Python script based on [PySAML2](https://github.com/rohe/pysaml2) and [freeradius_pysaml2](https://github.com/rohe/freeradius_pysaml2.git). With this script you can test your SAML2 Identity Provider's ECP capabilities. 

## prepare

1. `sudo apt-get install python-setuptools python-dev libffi-dev xmlsec1`
2. `git clone https://github.com/sitya/pysaml2.git`
3. `cd pysaml2 && sudo ./setup.py install`
4. `cd /usr/local/etc && git clone https://github.com/sitya/ecp_client.git` # This repository
5. `cd ecp_client`

## configure

1. Generate a self-signed cert into the created `pki` directory named as `ssl.key` and `ssl.cert` For exímple: `mkdir pki && cd pki && openssl genrsa 2048 > ssl.key && openssl req -new -x509 -nodes -sha1 -days 3650 -key ssl.key > ssl.cert`
2. Generate `sp.xml` metadata file contains SAML2 metadata of this "SP" (This ecp client will behave as an SP, and the IdP has to know the metadata of this SP). You can do it manually, or there is a [tool](https://github.com/rohe/pysaml2/blob/ae9d27e5100f002f55ad6eb2b252a0aa5f16a336/tools/make_metadata.py) coming with `pysaml2`
3. You have to give this metadata to the IdP. Do it as you like: using federation register tool, or feed it directly with the IdP
4. Grab the metadata of the IdP you want to test and save it as `idp.xml`.

## run

`./ecp_client`

Then look at the `STDOUT` for the result. You sould get something like this: http://pastebin.com/v8yXtHzD

