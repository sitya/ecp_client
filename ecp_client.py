#! /usr/bin/env python
#
# Copyright 2011 Roland Hedberg <roland.hedberg@adm.umu.se>
#
# The freeradius extension using ECP
#
import base64

__author__ = 'rolandh'
__version__ = "0.0.5a"

import pprint
import saml2
import sys
import traceback
import requests

from saml2 import saml

from saml2.client import Saml2Client
from saml2.response import authn_response
from saml2.ecp_client import Client

# Where's the configuration file is
CONFIG_DIR = "./"
sys.path.insert(0, CONFIG_DIR)

import config

# Globals
CLIENT = None
ECP = None
MAX_STRING_LENGTH = 247

requests.packages.urllib3.disable_warnings()

def eq_len_parts(txt, delta=250):
    res = []
    n = 0
    strlen = len(txt)
    while n <= strlen:
        m = n + delta
        res.append("".join(txt[n:m]))
        n = m
    return res


def exception_trace(tag, exc, log):
    message = traceback.format_exception(*sys.exc_info())
    log.error("[%s] ExcList: %s" % (tag, "".join(message),))
    log.error("[%s] Exception: %s" % (tag, exc))


def log(level, s):
    """Log function."""
    print level, ':' , s

class LOG(object):
    def info(self, txt):
        log('info', txt)

    def error(self, txt):
        log('error', txt)

    def debug(self, txt):
        log('debug', txt)

    def warning(self, txt):
        log('error', txt) # Not absolutely correct just an approximation


logger = LOG()
    

#noinspection PyUnusedLocal
def instantiate(p):
    """Module Instantiation.  0 for success, -1 for failure.
    """
    global CLIENT
    global ECP

    # Use IdP info retrieved from the SP when metadata is missing

    try:
        CLIENT = Saml2Client(config_file=config.CONFIG)
    except Exception, err:
        # Report the error and return -1 for failure.
        # xxx A more advanced module would retry the database.
        exception_trace("instantiate", err, LOG())
        log('error', str(err))
        return -1

    logger.info('Saml2Client initialized')

    try:
        try:
            _passwd = config.PASSWD
        except AttributeError:
            _passwd = ""

        try:
            _certs = CLIENT.config.ca_certs
            _disable = False
        except (KeyError, AttributeError):
            _certs = ""
            _disable = True

        ECP = Client("", _passwd, None, metadata_file=config.METADATA_FILE,
                     xmlsec_binary=CLIENT.config.xmlsec_binary,
                     ca_certs=_certs,
                     disable_ssl_certificate_validation=_disable,
                     key_file=CLIENT.config.key_file)
        logger.info('ECP client initialized')

    except Exception, err:
        exception_trace("instantiate", err, logger)
        return -1

    if len(CLIENT.metadata.metadata) == len(ECP.metadata.metadata):
        if not CLIENT.metadata.metadata.values()[0] == ECP.metadata.metadata.values()[0]:
            logger.info("metadata differs between SP and ECP client")

    return 0


def authentication_request(cls, ecp, idp_entity_id, destination, sign=False):
    """ Does a authentication request to an Identity provider.
    This function uses the SOAP binding other bindings could be used but are
    not supported right now.

    :param cls: The SAML2 client instance
    :param ecp: The ECP client instance
    :param idp_entity_id: The identifier of the subject
    :param destination: To whom the query should be sent
    :param sign: Whether the request should be signed or not
    :return: A Authentication Response
    """

    acsus = cls.config.endpoint('assertion_consumer_service',
                                saml2.BINDING_PAOS)
    if not acsus:
        raise Exception("Couldn't find own SOAP endpoint")

    acsu = acsus[0]

    req_id, request = cls.create_authn_request(
        destination, service_url_binding=acsu, sign=sign, sign_prepare=True,
        binding=saml2.BINDING_PAOS, nameid_format=saml.NAMEID_FORMAT_PERSISTENT)

    try:
        try:
            headers = [(config.USERNAME_HEADER, ecp.user)]
        except AttributeError:
            headers = None

        if ecp.passwd:  # Set HTTP Basic authentication header
            _str = base64.b64encode("%s:%s" % (ecp.user, ecp.passwd))
            headers.append(("Authorization", "Basic %s" % _str))

        logger.info("Headers: {0:>s}".format(headers))
        logger.info("Request: %s" % request)

        # send the request and receive the response
        response = ecp.phase2(request, acsu, idp_entity_id, headers,
                              sign)
    except Exception, exc:
        exception_trace("soap", exc, logger)
        logger.info("SoapClient exception: %s" % (exc,))
        return None

    if response:
        try:
            # synchronous operation
            aresp = authn_response(cls.config, acsu, asynchop=False,
                                   allow_unsolicited=True)
            #aresp.debug = True
        except Exception, exc:
            logger.error("%s" % exc)
            return None

        try:
            _resp = aresp.load_instance(response).verify()
        except Exception, err:
            logger.error("%s" % err)
            return None

        if _resp is None:
            logger.error("Didn't like the response")
            return None

        return _resp.assertion
    else:
        return None


def only_allowed_attributes(client, assertion, allowed):
    res = []
    _aconvs = client.config.attribute_converters

    for statement in assertion.attribute_statement:
        for attribute in statement.attribute:
            if attribute.friendly_name:
                fname = attribute.friendly_name
            else:
                fname = ""
                for acv in _aconvs:
                    if acv.name_form == attribute.name_form:
                        fname = acv._fro[attribute.name]

            if fname in allowed:
                res.append(attribute)

    return assertion


def post_auth(authdata):
    """ Attribute aggregation after authentication
    This is the function that is accessible from the freeradius server core.

    :return: A 3-tuple
    """

    global CLIENT
    global ECP

    # Extract the data we need.
    servicename = "host"
    hostname = "ms-sp.aai.niif.hu"

    for t in authdata:
        if t[0] == 'User-Name':
            username = t[1][1:-1]
        elif t[0] == "User-Password":
            password = t[1][1:-1]

    ECP.user = username
    ECP.passwd = password

    _srv = "%s:%s" % (servicename, hostname)
    log('info', "Working on behalf of: %s" % _srv)

    # Find the endpoint to use
    sso_service = ECP.metadata.single_sign_on_service(config.IDP_ENTITYID,
                                                      saml2.BINDING_SOAP)
    if not sso_service:
        log('debug',
            "Couldn't find an single-sign-on endpoint for: %s" % (
                config.IDP_ENTITYID,))
        return False

    location = sso_service[0]["location"]

    if config.DEBUG:
        log('debug', "location: %s" % location)

    #ECP.http.clear_credentials()
    if config.DEBUG:
        log('debug', "Login using user:%s password:'%s'" % (ECP.user,
                                                                  ECP.passwd))

    _assertion = authentication_request(CLIENT, ECP,
                                        config.IDP_ENTITYID,
                                        location,
                                        sign=config.SIGN)

    if config.DEBUG:
        log('debug', "Assertion: %s" % _assertion)

    if _assertion is None:
        return False

    if _assertion is False:
        log('debug', "IdP returned: %s" % CLIENT.server.error_description)
        return False

    # remove the subject confirmation if there is one
    _assertion.subject.subject_confirmation = []

    if config.DEBUG:
        log('debug', "Assertion: %s" % _assertion)

    # Log the success
    log('info', 'user accepted: %s' % (username, ))


    ret = CLIENT.parse_authn_request_response(_assertion,saml2.BINDING_SOAP)
    
    print('\nResponse: ')
    return _assertion


# Test the modules
if __name__ == '__main__':
    instantiate(None)
    #    print authorize((('User-Name', '"map"'), ('User-Password', '"abc"')))
    print post_auth(
        (('User-Name', '"student"'), ('User-Password', '"studentpass"')))

