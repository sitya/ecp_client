from saml2.saml import NAME_FORMAT_URI
from saml2 import BINDING_PAOS

# *** Change this line ***
BASE= "https://dev.aai.niif.hu/"

# Don't change this line unless you know exactly what you are doing
BASEDIR = "/usr/local/etc/ecp_client/"

CONFIG = {
    "entityid" : BASE + "ecp_client",
    "description": "TEST ECP client",
    "service": {
        "sp":{
            "name" : "TEST ECP client",
            "endpoints":{
                "assertion_consumer_service": [BASE,
                                               (BASE+"ECP", BINDING_PAOS)],
            },
            # ** These you might want to change **
#            "required_attributes": ["surname", "givenName",
#                                    "eduPersonAffiliation"],
#            "optional_attributes": ["title"],
        }
    },
    "debug" : 1,
    "key_file" : BASEDIR + "pki/ssl.key",
    "cert_file" : BASEDIR + "pki/ssl.cert",
    "attribute_map_dir" : BASEDIR + "attributemaps",
    "metadata" : {
       "local": [BASEDIR + "idp.xml"],
    },
    # in case xmlsec1 isn't anywhere normal
    "xmlsec_binary":"/usr/bin/xmlsec1",
    "name_form": NAME_FORMAT_URI,
    # -- below used by make_metadata --
    # ** These you probably want to change **
    "organization": {
        "name": "NIIFI AAI",
        "display_name": [("NIIFI AAI","se"),("NIIFI AAI","en")],
        "url":"http://www.niif.hu",
    },
    "contact_person": [{
        "given_name":"AAI",
        "sur_name": "NIIFI",
        "email_address": ["aai@niif.hu"],
        "contact_type": "technical",
        },
    ],
    # You may want to uncomment this
    "logger": {
       "rotating": {
           "filename": "/usr/local/etc/ecp_client/radius_sp.log",
           "maxBytes": 100000000,
           "backupCount": 5,
       },
       "loglevel": "debug",
   }
}

