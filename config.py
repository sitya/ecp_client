CONFIG = 'pysaml_config.py'                # PySAML2 Configuration file name

METADATA_FILE="/usr/local/etc/ecp_client/idp.xml"

DEBUG=0

# Should the SP sign the request ?
SIGN=True

# This is needed in order to pick information about the right IdP from the
# metadata file. This must be the entity ID of the IdP not an endpoint
IDP_ENTITYID = "https://dev.aai.niif.hu/ecp/saml2/idp/metadata.php"

# The password that should be used when authenticating with the IdP
# This password will be used disregarding which user it is.

PASSWD = ""

# If you don't want to used Basic-Auth you can place the username in a
# header. This defines the header name

USERNAME_HEADER = "ECP-Username"

USE_RADIUS_PASSWD = True
