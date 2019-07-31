#!/usr/bin/env python3
import datetime
import re
from dateutil import parser
import xml.etree.ElementTree as ET
import hashlib
import struct
import hmac
import base64
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import simplejson as json
import os
import sys
import urllib
import boto3
import requests
import botocore
import configparser
import logging
import click_log
import click
import time
import keyring
import yaml
log = logging.getLogger(__name__)
click_log.basic_config(log)


def get_totp_token(totp_secret):
    now = int(time.time())
    remain_seconds = now % 30
    intervals_no = int(time.time())//30
    # if it is close to the end of 30 seconds, wait a bit to avoid time syncing symptoms
    if remain_seconds > 28:
        time.sleep(31-remain_seconds)
        intervals_no += 1
    key = base64.b32decode(totp_secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = ord(chr(h[19])) & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h


class Settings(object):
    def __init__(self, home='~', aws_credentials_file_path='~/.aws/credentials'):
        self.home = os.path.abspath(os.path.expanduser(home))
        self.work_dir = os.path.join(self.home, '.aws', 'okta-aws')
        if not os.path.isdir(self.work_dir):
            os.makedirs(self.work_dir)
        self.okta_sid = os.path.join(self.work_dir, 'okta_sid')
        self.aws_credentials_file_path = os.path.expanduser(aws_credentials_file_path)
        self.okta_aws_settings_path = os.path.join(self.work_dir, 'settings.json')
        try:
            with open(self.okta_aws_settings_path) as f:
                config = json.load(f)
        except:
            config = {}
        self.sso_url = config.get("sso_url", '')
        self.region = config.get("region", '')
        self.user_name = config.get("user_name", '')
        self.password = config.get("password", '')
        self.google_2fa_totp = config.get("google_2fa_totp", '')
        self.token_duration_second = 43200

    def save(self):
        with open(self.okta_aws_settings_path, 'w') as f:
            f.write(json.dumps({
                'sso_url': self.sso_url,
                'region': self.region,
                'user_name': self.user_name,
                'password': self.password,
                'google_2fa_totp': self.google_2fa_totp,

            }, indent=2))
        os.chmod(self.okta_aws_settings_path, mode=0o600)


@click.group()
@click.option('--home', default='~')
@click.option('--aws-credentials-file-path', default='~/.aws/credentials')
@click.pass_context
def cli(ctx, home, aws_credentials_file_path):
    ctx.obj = Settings(home, aws_credentials_file_path)


def collect_okta_info(settings):
    log.debug('working dir: %s', settings.work_dir)
    # interactive way of creating keyring
    sso_url = input("Please input your oka app sso url. (It should be like https://<company>.okta.com/home/amazon_aws/<app-id>/sso/saml. For Domain, it is https://domain.okta.com/app/amazon_aws/exknj7gedfU7s4FB8355/sso/saml). Current value: %s\n" % settings.sso_url)
    if sso_url:
        settings.sso_url = sso_url
    region = input("Please input AWS region. If not provided, it will be ap-southeast-2. Current value: %s\n" % settings.region)
    if not region:
        settings.region = 'ap-southeast-2' if not settings.region else settings.region
    else:
        settings.region = region
    user_name = input("Please provide okta user name, (your email address). Current value: %s \n" % settings.user_name)
    if user_name:
        settings.user_name = user_name
    settings.password = input("Please provide okta password. Must re-input every time you execute this: \n")
    google_2fa_totp = input(
        "Please provide Google App TOTP token (You can use a QR code reader to scan your google 2FA barchar code while you are setting up your 2FA). No input means no change to current value. \n")
    if google_2fa_totp:
        settings.google_2fa_totp = google_2fa_totp
    log.info("Writting above information into OSX keychain...")
    settings.save()

    return settings


def create_profiles(settings):
    saml_dict = refresh_saml_resp(settings)
    log.debug("You have permissions to these roles: %s", saml_dict['RoleArns'])
    config = configparser.RawConfigParser()
    if not os.path.isfile(settings.aws_credentials_file_path):
        log.debug('Need to create aws credentials file %s', settings.aws_credentials_file_path)
        with open(settings.aws_credentials_file_path, 'a'):
            os.utime(settings.aws_credentials_file_path, None)
    log.debug('Using aws credential file %s', settings.aws_credentials_file_path)
    with open(settings.aws_credentials_file_path, 'r') as f:
        config.read_file(f)
        log.debug('Existing sections, %s', config.sections())
        for role in saml_dict['RoleArns'].keys():
            section = get_role_key(role)
            if config.has_section(section):
                config.remove_section(section)
            config.add_section(section)
            config.set(section, 'credential_process',
                       ' '.join('"%s"' % p for p in (
                           'okta-aws-cred-helper',
                           'get-cred',
                           '--role-arn',
                           role,
                       )))
            config.set(section, 'region', settings.region)
        log.debug('Refresh profile section %s', section)
        log.debug('Add an empty profile to avoid a potential dead lock')
        if not config.has_section('okta-empty'):
            config.add_section('okta-empty')
    log.debug("Updating AWS credentials file: %s", settings.aws_credentials_file_path)
    with open(settings.aws_credentials_file_path, 'w') as wf:
        config.write(wf)


def _okta_cookie_login(sid, idp_entry_url):
    session = requests.Session()

    """Attempts a login using the provided sid cookie value. Returns a
    requests.Response object. The Response object may or may not be a
    successful login containing a SAML assertion"""
    # Create Cookie Dict and add sid value
    cookie_dict = {}
    cookie_dict['sid'] = sid

    cookie_url = idp_entry_url

    cookie_response = session.get(cookie_url, verify=True, cookies=cookie_dict)

    return cookie_response


def _get_saml_assertion(response):
    """Parses a requests.Response object that contains a SAML assertion.
    Returns an base64 encoded SAML Assertion if one is found"""
    # Decode the requests.Response object and extract the SAML assertion
    soup = BeautifulSoup(response.text, "html.parser")
    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            return inputtag.get('value')


def _handleApiError(response):
    send_result = json.loads(response.text)

    error_code = send_result['errorCode']
    error_summary = send_result['errorSummary']

    log.error("{code} - {summary}".format(code=error_code, summary=error_summary))
    exit(2)


def _factorGoogle(factor_url, factor_name, stateToken, settings):
    session = requests.Session()
    session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json', 'Cache-Control': 'no-cache'})

    payload = {'stateToken': stateToken}

    send_response = session.post(factor_url, data=json.dumps(payload), verify=True)

    if send_response.status_code == 200:
        passcode = get_totp_token(totp_secret=settings.google_2fa_totp)
        payload = {'stateToken': stateToken, 'passCode': passcode}

        verify_response = session.post(factor_url, data=json.dumps(payload), verify=True)

        if verify_response.status_code == 200:
            verify_result = json.loads(verify_response.text)
            if 'sessionToken' not in verify_result:
                log.error("Failed to login. Please check if password or 2FA is correct. Details: %s", json.dumps(verify_result, indent=2))
                sys.exit(1)
            return verify_result['sessionToken']
        elif verify_response.status_code in (403, 429):
            _handleApiError(verify_response)
    elif send_response.status_code in (403, 429):
        _handleApiError(send_response)


def _okta_mfa_login(password_login_response, settings):
    authn_stateToken = password_login_response['stateToken']
    factor_list = [f for f in password_login_response['_embedded']['factors']
                   if f.get('provider') == 'GOOGLE' and f.get('factorType') == 'token:software:totp']
    if not factor_list:
        log.error("OKTA does not support Google 2FA")
        sys.exit(1)
    return _factorGoogle(factor_list[0]['_links']['verify']['href'],
                         factor_list[0]['factorType'],
                         authn_stateToken, settings)


def _okta_password_login(username, password, sso_url, settings):
    session = requests.Session()
    session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json', 'Cache-Control': 'no-cache'})

    parsedurl = urlparse(sso_url)

    authn_payload = {'username': username,
                     'password': password,
                     'options': {
                         'multiOptionalFactorEnroll': True,
                         'warnBeforePasswordExpired': True
                     }
                     }

    authn_url = "{scheme}://{netloc}{action}".format(
        scheme=parsedurl.scheme,
        netloc=parsedurl.netloc,
        action="/api/v1/authn")
    # Performs the submission of the IdP login form with the above post data
    authn_response = session.post(authn_url, data=json.dumps(authn_payload), verify=True)

    if authn_response.status_code == 200:
        authn_result = json.loads(authn_response.text)
        authn_status = authn_result['status']

        if authn_status == "MFA_REQUIRED":
            sessionToken = _okta_mfa_login(authn_result, settings)
        else:
            sessionToken = authn_result['sessionToken']

        saml_url = "{url}?onetimetoken={sessiontoken}".format(
            url=sso_url,
            sessiontoken=sessionToken)

        saml_response = session.get(saml_url, verify=True)

        return saml_response
    elif authn_response.status_code in (401, 403, 429):
        _handleApiError(authn_response)


def _write_sid_file(sid_file, sid):
    """Writes a given sid to a file. Returns nothing"""
    sid_cache_file = os.open(sid_file, os.O_WRONLY | os.O_CREAT, mode=0o600)
    os.write(sid_cache_file, sid.encode())
    os.close(sid_cache_file)


def _get_arns_from_assertion(assertion):
    """Parses a base64 encoded SAML Assertion and extracts the role and 
    principle ARNs to be used when making a request to STS.
    Returns a dict with RoleArn, PrincipalArn & SAMLAssertion that can be 
    used to call assume_role_with_saml"""
    # Parse the returned assertion and extract the principle and role ARNs
    root = ET.fromstring(base64.b64decode(assertion))
    urn = "{urn:oasis:names:tc:SAML:2.0:assertion}"
    urn_attribute = urn + "Attribute"
    urn_attributevalue = urn + "AttributeValue"
    role_url = "https://aws.amazon.com/SAML/Attributes/Role"

    arns = {}  # role-arn:principal-arn
    for saml2attribute in root.iter(urn_attribute):
        if (saml2attribute.get('Name') == role_url):
            for saml2attributevalue in saml2attribute.iter(urn_attributevalue):
                dirty_arns = saml2attributevalue.text.split(',')
                arns[dirty_arns[1]] = dirty_arns[0]

    # Create dict to be used to call assume_role_with_saml
    arn_dict = {}
    arn_dict['SAMLAssertion'] = assertion
    arn_dict['RoleArns'] = arns
    return arn_dict


def refresh_saml_resp(settings):
    sid = 'x'
    if os.path.isfile(settings.okta_sid):
        with open(settings.okta_sid) as sid_file:
            sid = sid_file.read()
    assertion = _get_saml_assertion(_okta_cookie_login(sid, settings.sso_url))
    # if the assertion equals None, means there was no sid, the sid expired
    # or is otherwise invalid, so do a password login
    if assertion is None:

        response = _okta_password_login(settings.user_name,
                                        settings.password,
                                        settings.sso_url,
                                        settings)
        assertion = _get_saml_assertion(response)
        if assertion is None:
            log.error("No valid SAML assertion retrieved!")
            sys.exit(1)
            # write sid for later use
        log.debug('Refreshed sid.')
        with open(settings.okta_sid, 'w') as f:
            f.write(response.cookies['sid'])
        os.chmod(settings.okta_sid, mode=0o600)
        log.debug('Saved sid locally for next time use.')
    saml_dict = _get_arns_from_assertion(assertion)
    return saml_dict


def _get_sts_token(RoleArn, PrincipalArn, SAMLAssertion, DurationSeconds):
    log.debug("Getting STS temporary token for role '%s'", RoleArn)
    sts_client = boto3.session.Session(profile_name='okta-empty').client('sts')
    response = sts_client.assume_role_with_saml(RoleArn=RoleArn,
                                                PrincipalArn=PrincipalArn,
                                                SAMLAssertion=SAMLAssertion,
                                                DurationSeconds=DurationSeconds)
    Credentials = response['Credentials']
    return Credentials

def load_aliases(file=None):
    if not file:
      file = os.path.join(os.path.dirname(__file__),'data', 'data.yaml')
    try:
      with open(file) as f:
        data = yaml.load(f, Loader=yaml.SafeLoader)
        return data['aliases']
    except:
      log.warning('Failed to load file %s, continue', file)
      return {}

aliases = None

def get_role_key(role_arn):
    # convert role arn into <acc-id>-<rolepaths>
    global aliases
    if aliases is None:
      aliases = load_aliases()
    tokens = role_arn.split(':')
    acc_id = aliases.get(tokens[-2], tokens[-2]).lower()
    role_name = tokens[-1]
    if role_name.startswith('role/'):
        role_name = role_name[5:]
    role_name = re.sub('[^0-9a-zA-Z]+', '-', role_name)
    return 'okta-%s-%s' % (acc_id, role_name)


def _refresh_credentials(role, settings):
    saml_dict = refresh_saml_resp(settings)
    log.debug("You have permissions to these roles: %s", saml_dict['RoleArns'])
    if role not in saml_dict['RoleArns']:
        log.error("You are not allowed to assume role: '%s'", role)
        exit(1)
    aws_creds = _get_sts_token(role,
                               saml_dict['RoleArns'][role],
                               saml_dict['SAMLAssertion'],
                               settings.token_duration_second)
    aws_creds['Version'] = 1
    aws_creds['SecurityToken'] = aws_creds['SessionToken']
    aws_creds['_ExpireEpoch'] = aws_creds['Expiration'].timestamp()
    log.debug("Received credentials: %s", aws_creds)
    return aws_creds


def get_credential(role, settings, return_value=False, format='json'):
    cache_file = os.path.join(settings.work_dir, get_role_key(role))
    creds_refreshed = True
    if os.path.isfile(cache_file):
        try:
            with open(cache_file) as f:
                aws_creds = json.loads(f.read())
            ttl = aws_creds['_ExpireEpoch']-datetime.datetime.now().timestamp()
            if ttl < 30:  # about to expire within 30 seconds
                log.debug("Cached credential expired. Need to refresh.")
            else:
                creds_refreshed = False
                if return_value:
                    return aws_creds
                else:
                    print_data(aws_creds, format=format)
                    return
        except:
            log.warning("Current cache '%s' does not seem valid. Need to refresh.", cache_file)
    aws_creds = _refresh_credentials(role, settings)
    log.debug('Retrieved new sid and saved it.')
    if creds_refreshed:
        with open(cache_file, 'w') as f:
            f.write(json.dumps(aws_creds, default=str))
        os.chmod(cache_file, mode=0o600)
    if return_value:
        return aws_creds
    else:
        print_data(aws_creds, format=format)

def print_data(aws_creds, format='json'):
  if format == 'json':
    print(json.dumps(aws_creds, default=str))
  elif format == 'eval':
    print("AWS_ACCESS_KEY_ID='%s' ; export AWS_ACCESS_KEY_ID" % aws_creds['AccessKeyId'])
    print("AWS_SECRET_ACCESS_KEY='%s' ; export AWS_SECRET_ACCESS_KEY"  % aws_creds['SecretAccessKey'])
    print("AWS_SECURITY_TOKEN='%s' ; export AWS_SECURITY_TOKEN" % aws_creds['SessionToken'])
    print("AWS_SESSION_TOKEN='%s' ; export AWS_SESSION_TOKEN" % aws_creds['SessionToken'])
    print("AWS_TEMP_KEY_EXPIRATION='%s' ; export AWS_TEMP_KEY_EXPIRATION" % aws_creds['Expiration'])
  elif format == 'aws':
    print('[default]')
    print("aws_access_key_id = %s"  % aws_creds['AccessKeyId'])
    print("aws_secret_access_key = %s" % aws_creds['SecretAccessKey'])
    print("aws_session_token = %s " % aws_creds['SessionToken'])
  else:
    raise ValueError("Cannot print in format %s", format)

def get_assumed_role_credential(from_role_arn, from_profile, to_role_arn, settings, format='json'):
    cache_file = os.path.join(settings.work_dir, get_role_key(to_role_arn))
    creds_refreshed = True
    if os.path.isfile(cache_file):
        try:
            with open(cache_file) as f:
                aws_creds = json.loads(f.read())
            ttl = aws_creds['_ExpireEpoch']-datetime.datetime.now().timestamp()
            if ttl < 30:  # about to expire within 30 seconds
                log.debug("Cached credential expired. Need to refresh.")
            else:
                creds_refreshed = False
                print_data(aws_creds, format=format)
                return
        except:
            log.warning("Current cache '%s' does not seem valid. Need to refresh.", cache_file)

    if from_profile:
        client = boto3.session.Session(profile_name=from_profile).client('sts')
    else:
        creds = get_credential(from_role_arn, settings, return_value=True)
        client = boto3.session.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        ).client('sts')
    aws_creds = client.assume_role(
        RoleArn=to_role_arn,
        RoleSessionName='okta-aws',
    )['Credentials']
    aws_creds['Version'] = 1
    aws_creds['SecurityToken'] = aws_creds['SessionToken']
    aws_creds['_ExpireEpoch'] = aws_creds['Expiration'].timestamp()
    if creds_refreshed:
        with open(cache_file, 'w') as f:
            f.write(print_data(aws_creds, format=format))
        os.chmod(cache_file, mode=0o600)
    print_data(aws_creds, format)

@cli.command()
@click.pass_obj
@click_log.simple_verbosity_option(log)
def init(settings):
    collect_okta_info(settings)


@cli.command()
@click.pass_obj
@click_log.simple_verbosity_option(log)
def refresh(settings):
    log.debug('working dir: %s', settings.work_dir)
    # interactive way of creating okta_sid
    create_profiles(settings)


@cli.command()
@click.pass_obj
@click_log.simple_verbosity_option(log)
@click.option('--role-arn', help='The AWS Role Arn to get temporary credential of.')
@click.option('--format', help='Using which format. by default it is json (which is used by this program).',
  default='json', type=click.Choice(['json', 'eval', 'aws']))
def get_cred(settings, role_arn, format):
    get_credential(role_arn, settings, format=format)


@cli.command()
@click.pass_obj
@click_log.simple_verbosity_option(log)
@click.option('--from-role-arn', help='The Root AWS role.', default=None)
@click.option('--from-profile', help='The Root AWS profile.', default=None)
@click.option('--to-role-arn', help='The AWS Role to be assumed to.')
def assume_role(settings, from_role_arn, from_profile, to_role_arn):
    if not from_role_arn and not from_profile:
        log.error("Must provide either from-role-arn or from-profile.")
        sys.exit(1)
    if from_role_arn and from_profile:
        log.error("Can't provide both from-role-arn and from-profile.")
        sys.exit(1)
    get_assumed_role_credential(from_role_arn, from_profile, to_role_arn, settings)

@cli.command()
@click.pass_obj
@click_log.simple_verbosity_option(log)
@click.option('--role-arn', help='The AWS Role Arn to get temporary credential of.')
def export_cred(settings, role_arn):
    get_credential(role_arn, settings, format='eval')


if __name__ == '__main__':
    cli()
