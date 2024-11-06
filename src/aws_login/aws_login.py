#!/usr/bin/env python
# -*- coding: UTF-8 -*-

'''
A simple tool to dump session credentials or open the AWS Management Console as a given user identity.

Can get credentials from env, or named config, or SSO login.

(c) Copyright Dave Heller 2024
'''

import boto3
import botocore.exceptions
import datetime
import json
import logging
import os
import pyperclip
import sys
import time
import requests
import subprocess
import urllib.parse
import webbrowser

from optparse import OptionParser


# --------------------------------------------------------------------------------------------------
# Functions...
# --------------------------------------------------------------------------------------------------
def construct_federated_url(ctx):
    '''
    Construct a URL that can open the AWS Console for a given user identity.

    Using the credentials from ctx.session, create the "getSigninToken" request
    and send it, then use the token to build the console URL.
    '''

    aws_federated_signin_endpoint = 'https://signin.aws.amazon.com/federation'

    credentials = ctx.session.get_credentials()

    session_data = {
        'sessionId': credentials.access_key,
        'sessionKey': credentials.secret_key,
        'sessionToken': credentials.token,
    }

    # Make a request to the AWS federation endpoint to get a sign-in token.
    s = requests.Session()
    r = requests.Request(
        'GET',
        aws_federated_signin_endpoint,
        params={
            'Action': 'getSigninToken',
            'DurationSeconds': str(datetime.timedelta(hours=12).seconds),
            'Session': json.dumps(session_data),
        },
    ).prepare()
    logging.info('1. The "getSigninToken" request is: %s' % r.url)
    response = s.send(r)
    response.raise_for_status()

    signin_token = json.loads(response.text)
    logging.info('Got "SigninToken" token from the AWS sign-in federation endpoint.')

    # Make a federated URL that can be used to sign into the AWS Management Console.
    query_string = urllib.parse.urlencode(
        {
            'Action': 'login',
            'Destination': 'https://console.aws.amazon.com/',
            'SigninToken': signin_token['SigninToken'],
        }
    )
    federated_url = f'{aws_federated_signin_endpoint}?{query_string}'
    logging.info('2. The "login" request is: %s' % federated_url)

    return federated_url


def get_session_token(ctx):
    '''
    Get session credentials from static credentials, update ctx.session with the new credentials.
    '''

    sts_client = ctx.session.client('sts')

    response = sts_client.get_session_token(
        DurationSeconds = 3600,  # TODO make configurable
    )

    new_session = boto3.Session(
        aws_access_key_id = response['Credentials']['AccessKeyId'],
        aws_secret_access_key = response['Credentials']['SecretAccessKey'],
        aws_session_token = response['Credentials']['SessionToken']
    )
    ctx.session = new_session


def get_federation_token(ctx):
    '''
    Get federated credentials from static credentials, update ctx.session with the new credentials.
    '''

    sts_client = ctx.session.client('sts')

    response = sts_client.get_federation_token(
        DurationSeconds = 3600,  # TODO make configurable
        Name = options.role_sessionname,
        # Permissions are the intersection of IAM user policies and PolicyArns, see docs.
        PolicyArns = [{'arn': 'arn:aws:iam::aws:policy/AdministratorAccess'}]
    )

    new_session = boto3.Session(
        aws_access_key_id = response['Credentials']['AccessKeyId'],
        aws_secret_access_key = response['Credentials']['SecretAccessKey'],
        aws_session_token = response['Credentials']['SessionToken']
    )
    ctx.session = new_session


def assume_roles(ctx):
    '''
    Do one or more assumeRoles on a list of Arns, update ctx.session with the final credentials.
    '''

    roles = read_list_fom_input('--assume-roles', options.assume_roles)

    for role in roles:

        sts_client = ctx.session.client('sts')

        response = sts_client.assume_role(
            RoleArn = role,
            RoleSessionName = options.role_sessionname
        )

        # Get the credentials from the JSON response
        access_key = response['Credentials']['AccessKeyId']
        secret_key = response['Credentials']['SecretAccessKey']
        token = response['Credentials']['SessionToken']

        # Update the session credentials by replacing the ctx.session
        new_session = boto3.Session(
            aws_access_key_id = access_key,
            aws_secret_access_key = secret_key,
            aws_session_token = token
        )
        ctx.session = new_session


def copy_url_to_clipboard(url):
    try:
        logging.info('Attempting to copy URL to clipboard... ')
        pyperclip.copy(url)
    except pyperclip.PyperclipException:
        logging.info('could not copy.')
    else:
        logging.info('successfully copied.')


def do_sso_login():
    '''
    Do the full AWS SSO login and return accessToken.
    '''

    # Create an SSO OIDC client
    sso_oidc = boto3.client('sso-oidc', region_name=options.sso_region)

    # Register the client
    if options.nrt == True:
        # Crude way to request non-refreshable accessToken.
        client = sso_oidc.register_client(
            clientName = 'aws-login.py',
            clientType = 'public'
        )
    else:
        client = sso_oidc.register_client(
            clientName = 'aws-login.py',
            clientType = 'public',
            scopes = ['sso:account:access']
        )

    # Get the client ID and client secret from the response
    client_id = client.get('clientId')
    client_secret = client.get('clientSecret')

    # Start the device authorization flow and get the device code, user code, and verification URI
    device_code_response = sso_oidc.start_device_authorization(
        clientId = client_id,
        clientSecret = client_secret,
        startUrl = options.start_url
    )

    device_code = device_code_response.get('deviceCode')
    user_code = device_code_response.get('userCode')
    verification_uri = device_code_response.get('verificationUri')

    url = f'{verification_uri}?user_code={user_code}'

    print(f'Your device authorization code is:\n{user_code}\n')
    print(f'Please go to {url} to authorize this device')

    copy_url_to_clipboard(url)

    if options.no_browser == False:
        print('Attempting to automatically open browser window for URL...')
        webbrowser.open_new_tab(url)

    # Poll the token endpoint until the user completes the authorization or the code expires
    while True:
        try:
            # Create a token with the device code, client ID and client secret...
            token_response = sso_oidc.create_token(
                clientId =  client_id,
                clientSecret = client_secret,
                grantType = 'urn:ietf:params:oauth:grant-type:device_code',
                deviceCode = device_code
            )
            # If successful...
            break
        except botocore.exceptions.ClientError as e:
            # If the error is authorization pending, wait a few seconds and try again...
            if e.response['Error']['Code'] == 'AuthorizationPendingException':
                time.sleep(device_code_response.get('interval', 5))
            # If the error is expired token, exit.
            elif e.response['Error']['Code'] == 'ExpiredTokenException':
                print("The device code has expired. Please try again.")
                exit()
            # Otherwise...
            else:
                raise e

    # Get the accessToken from the response
    accessToken = token_response.get('accessToken')
    token_response.pop('ResponseMetadata')

    if (options.use_cache == True):
        expiry = datetime.datetime.utcnow(
        ) + datetime.timedelta(seconds=token_response['expiresIn'])

        cache = {}
        cache['startUrl'] = options.start_url
        cache['region'] = options.sso_region
        cache['clientId'] = client['clientId']
        cache['clientSecret'] = client['clientSecret']
        cache['accessToken'] = token_response['accessToken']
        cache['expiresIn'] = token_response['expiresIn']
        cache['expiresAt'] = expiry.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
        if 'refreshToken' in token_response:
            cache['refreshToken'] = token_response['refreshToken']

        # Write the cache file...
        write_accesstoken_cache(cache)

    return accessToken


def get_oidc_role_credentials(accessToken):
    '''
    Use a provided accessToken to get session credentials for the specified acct and SSO role.
    '''

    # Create an SSO client
    sso_client = boto3.client('sso', region_name=options.sso_region)

    # Get session credentials for an SSO role in an account
    # Now with autorefresh support.
    refresh_tried = False
    response = {}
    while True:

        try:
            response = sso_client.get_role_credentials(
                accessToken = accessToken,
                accountId = options.sso_acct_id,
                roleName = options.sso_role_name
            )

        except sso_client.exceptions.UnauthorizedException as e:
            print('Error (%s) %s' % (e.__class__.__name__, e))

            if options.refresh == 'off':
                exit(1)

            if options.accesstoken_cache == None:
                raise SystemExit('Sorry, no autorefesh available :-(')

            if refresh_tried == True:
                print('Look, we already did accessToken refresh and still we get:')
                raise SystemExit('Error: accessToken not valid: (%s) %s' % (
                    e.__class__.__name__, e))

            print('Trying auto-refresh...')
            refresh_tried = True
            try:
                accessToken = do_accesstoken_refresh()
            except Exception as ee:
                raise SystemExit('Error: accessToken refresh failed: (%s) %s' % (
                    ee.__class__.__name__, ee))

        except Exception as e:
            raise SystemExit('Error (%s) %s' % (e.__class__.__name__, e))

        else:
            break

    # Get the credentials from the JSON response
    role_credentials = response['roleCredentials']

    return role_credentials


def read_list_fom_input(option_name, input_value):

    output_list = []
    payload = ''

    if input_value != None:

        if (input_value == ''):
            raise ValueError('Error: empty value passed to "%s".' % option_name)

        loc = input_value.split('file://')

        if (len(loc) == 1):
            payload = loc[0]

        elif (len(loc) == 2):
            payload = open(loc[1], 'rt').read()

        elif (len(loc) > 2):
            raise ValueError('Error: unable to parse the value passed to "%s".' % option_name)

        try:
            # Valid JSON?
            output_list = json.loads(payload)

        except json.JSONDecodeError:
            # Must be a CSV.
            output_list = ''.join(payload.split()).split(',')

    return output_list


def read_dict_from_input(option_name, input_value):

    output_dict = {}
    payload = ''

    if input_value != None:

        if (input_value == ''):
            raise ValueError('Error: empty value passed to "%s".' % option_name)

        loc = input_value.split('file://')

        if (len(loc) == 1):
            payload = loc[0]

        elif (len(loc) == 2):
            payload = open(loc[1], 'rt').read()

        elif (len(loc) > 2):
            raise ValueError('Error: unable to parse the value passed to "%s".' % option_name)

        try:
            # Valid JSON?
            output_dict = json.loads(payload)

        except json.JSONDecodeError:
            raise ValueError('Error: input to "%s" must be valid JSON.' % option_name)

    return output_dict


def read_accesstoken_cache():
    '''
    Read the cached data into a python dict.
    '''

    cached_data = {}

    if options.accesstoken_cache == None:
        raise ValueError('Error: Need cache file to proceed; use --accesstoken-cache.')

    try:
        cached_data = read_dict_from_input('--accesstoken-cache', options.accesstoken_cache)
    except FileNotFoundError as e:
        raise SystemExit('Can\'t find the cache file, has it been created?')
    except Exception as e:
        raise SystemExit('Error (%s): cannot read cache: %s' % (
            e.__class__.__name__, e))

    if not isinstance(cached_data, dict):
        raise ValueError('Input to --accesstoken-cache must be a dict.')

    if cached_data == {}:
        raise ValueError('Input to --accesstoken-cache appears to be empty.')

    return cached_data


def get_cached_accesstoken():
    '''
    Read accessToken (and region) from the cache.
    '''

    cached_data = read_accesstoken_cache()

    try:
        cached_accessToken = cached_data['accessToken']
    except KeyError as e:
        raise SystemExit('Error (%s) %s is missing from the cache file.' % (
            e.__class__.__name__, e))

    options.sso_region = cached_data['region']

    return cached_accessToken


def do_accesstoken_refresh():
    '''
    Read refreshToken from the cache and do the refresh operation, return new accessToken.
    '''

    cached_data = read_accesstoken_cache()

    try:
        cached_data['startUrl']
        cached_data['region']
        cached_data['clientId']
        cached_data['clientSecret']
        cached_data['refreshToken']
    except KeyError as e:
        raise SystemExit('Error (%s): cannot do refresh: %s is missing from the cache file.' % (
            e.__class__.__name__, e))

    logging.info("--> Using SSO OIDC clientId: %s" % cached_data['clientId'])
    logging.info("--> Using SSO OIDC clientSecret: %s" % cached_data['clientSecret'][0:60] + '...')
    logging.info("--> Using SSO OIDC refreshToken: %s" % cached_data['refreshToken'][0:60] + '...')

    # Create an SSO OIDC client
    options.sso_region = cached_data['region']
    sso_oidc = boto3.client('sso-oidc', region_name=options.sso_region)

    # Get refreshed accessToken...
    token_response = sso_oidc.create_token(
        clientId =  cached_data['clientId'],
        clientSecret =  cached_data['clientSecret'],
        grantType = 'refresh_token',
        refreshToken = cached_data['refreshToken']
    )
    token_response.pop('ResponseMetadata')
    accessToken = token_response['accessToken']
    refreshToken = token_response['refreshToken']
    logging.info('--> The REFRESHED OIDC accessToken is: %s' % accessToken[0:60] + '...')
    logging.info('--> The REFRESHED OIDC refreshToken is: %s' % (refreshToken[0:60] + '...' if (
        refreshToken != cached_data['refreshToken']) else 'Unchanged'))

    if (options.use_cache == True):
        expiry = datetime.datetime.utcnow(
        ) + datetime.timedelta(seconds=token_response['expiresIn'])
        cache = {
            'startUrl' : cached_data['startUrl'],
            'region' : cached_data['region'],
            'clientId' : cached_data['clientId'],
            'clientSecret' : cached_data['clientSecret'],
            'accessToken' : token_response['accessToken'],
            'expiresIn' : token_response['expiresIn'],
            'expiresAt' : expiry.strftime('%Y-%m-%dT%H:%M:%S') + 'Z',
            'refreshToken' : token_response['refreshToken']
        }

        # Write the cache file...
        write_accesstoken_cache(cache)

    return accessToken


def import_accesstoken_cache():
    '''
    Read cached data from input and import it to our internal cache.
    '''

    cached_data = read_accesstoken_cache()

    try:
        cached_data['startUrl']
        cached_data['region']
        cached_data['clientId']
        cached_data['clientSecret']
        cached_data['accessToken']
    except KeyError as e:
        raise SystemExit('Error (%s) %s is missing from the cache file.' % (
            e.__class__.__name__, e))

    write_accesstoken_cache(cached_data)


def get_home_dir():
    if os.name == "posix": # Linux, Mac
        return os.environ["HOME"]
    elif os.name == "nt":  # Windows
        return os.environ["USERPROFILE"]
    else:
        raise NotImplementedError("Unsupported platform")


def get_cache_dir():
    return os.path.join(get_home_dir(), '.aws-login')


def get_cache_filename():
    cache_file = 'aws-accesstoken-cache.json'
    return os.path.join(get_cache_dir(), cache_file)


def make_cache_dir():
    try:
        os.makedirs(get_cache_dir(), exist_ok=True)
    except Exception as e:
        raise SystemExit('Error: cannot create cache dir: (%s)' % e.__class__.__name__)


def write_accesstoken_cache(cache):
        make_cache_dir()
        with open(get_cache_filename(), 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=4)
            f.write('\n')


def parse_arn(arn):
    '''
    Parse an AWS IAM role Arn into its constituent bits.
    :param arn: The Arn string to parse
    :return: A dict containing the parsed fields
    '''

    parts = arn.split(':')

    if len(parts) != 6:
        raise ValueError(f'Invalid Arn string: {arn}')

    if parts[0] != 'arn':
        raise ValueError(f'Invalid Arn string: {arn}')

    role_parts = parts[5].split('/')

    if len(role_parts) != 2:
        raise ValueError(f'Invalid Arn string: {arn}')

    if role_parts[0] != 'role':
        raise ValueError(f'Invalid Arn string: {arn}')

    return {
        'partition': parts[1],
        'service': parts[2],
        'region': parts[3],
        'acct_id': parts[4],
        'role_name': role_parts[1]
    }


# --------------------------------------------------------------------------------------------------
# Build AWS context including boto3 session...
# --------------------------------------------------------------------------------------------------
class AWSContextManager:
    def __init__(self, aws_profile, access_key, secret_key, token):
        self.aws_profile = aws_profile
        self.access_key = access_key
        self.secret_key = secret_key
        self.token = token

    def __enter__(self):
        self.session = boto3.Session(profile_name=self.aws_profile,
                                     aws_access_key_id=self.access_key,
                                     aws_secret_access_key=self.secret_key,
                                     aws_session_token=self.token)
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass



# --------------------------------------------------------------------------------------------------
# Run...
# --------------------------------------------------------------------------------------------------
def run():

    cmds_usage = '''\nAvailable commands:
    console
    dumpcreds
    runas
    getcallerid
    dumpconfig
    importcache
    '''.rstrip()

    usage = 'usage: %prog command [options]\n   ex: %prog console --profile "mySessionProfile"\n'
    parser = OptionParser(usage + cmds_usage)
    global options

    parser.add_option('--profile', dest='aws_profile', default=None,
                      help='AWS profile to use')
    parser.add_option('--assume-roles', dest='assume_roles', default=None,
                      help='Chained list of role Arns to assume')
    parser.add_option('--role-sessionname', dest='role_sessionname', default='aws-login',
                      help='RoleSessionName for --assume-role operations')
    parser.add_option('--get-session-token', dest='get_session_token', default=False,
                      action='store_true',
                      help='Get session credentials from static credentials')
    parser.add_option('--get-federation-token', dest='get_federation_token', default=False,
                      action='store_true',
                      help='Get federated credentials from static credentials')
    parser.add_option('--start-url', dest='start_url', default=None,
                      help='AWS SSO Start URL')
    parser.add_option('--sso-region', dest='sso_region', default='us-east-1',
                      help='AWS IdC instance region')
    parser.add_option('--sso-session-name', dest='sso_session_name', default='my-sso',
                      help='The sso_session identifier to use in your config file')
    parser.add_option('--sso-access-token', dest='sso_access_token', default=None,
                      help='Use the provided accessToken in lieu of new SSO login')
    parser.add_option('--sso-acct-id', dest='sso_acct_id', default=None,
                      help='Account ID for the SSO role to assume')
    parser.add_option('--sso-role-name', dest='sso_role_name', default=None,
                      help='The SSO role (permission set) to')
    parser.add_option('--target-arns', dest='target_arns', default=None,
                      help='List of target Arns for "assume role" profile entries (dumpconfig only)')
    parser.add_option('--no-browser', dest='no_browser', default=False,
                      action='store_true',
                      help='Do not attempt to open browser')
    parser.add_option('--outform', dest='outform', default='linux',
                      help='Format to dumpcreds: linux,mac,windows,powershell (default: linux)')
    parser.add_option('--refresh', dest='refresh', default='auto',
                      help='OIDC accessToken refresh: on,off,auto (default: auto)')
    parser.add_option('--use-cache', dest='use_cache', default=False,
                      action='store_true',
                      help='Enable accessToken caching and autorefresh')
    parser.add_option('--accesstoken-cache', dest='accesstoken_cache', default=None,
                      help='Use the provided accessToken cache file instead of the default file')
    parser.add_option('--nrt', dest='nrt', default=False,
                      action='store_true',
                      help='Request non-refreshable accessToken type (no scopes)')
    parser.add_option('-c', '--command', dest='command', default=None,
                      help='Command to execute for runas')
    parser.add_option('--region', dest='region', default=None,
                      help='AWS region for runas or dumpconfig')

    (options, args) = parser.parse_args()

    def need_accesstoken_cache():
        if options.accesstoken_cache == None:
            print('No cache file specified; use --accesstoken-cache.')
            exit(1)

    def need_command():
        if options.command == None:
            print('No command specified; use --command.')
            exit(1)

    operation = None

    if len(args) > 0:
        op = args[0].lower()
        if op == 'console':
            operation = op
        elif op == 'dumpcreds':
            operation = op
        elif op == 'getcallerid':
            operation = op
        elif op == 'runas':
            need_command()
            operation = op
        elif op == 'dumpconfig':
            operation = op
        elif op == 'importcache':
            need_accesstoken_cache()
            operation = op
        else:
            print('Unknown command: %s\n' % op)

    if operation == None:
        parser.print_help()
        exit(1)


    # ----------------------------------------------------------------------------------------------
    # Check input options...
    # ----------------------------------------------------------------------------------------------
    if (options.sso_acct_id != None and options.sso_role_name == None):
        raise ValueError('Option --sso-acct-id is of no use without --sso-role-name.')

    elif (options.sso_role_name != None and options.sso_acct_id == None):
        raise ValueError('Option --sso-role-name is of no use without --sso-acct-id.')

    elif (options.sso_role_name != None and options.sso_acct_id != None):
        if (options.start_url == None and options.sso_access_token == None and
                options.use_cache == False and options.accesstoken_cache == None):
            raise ValueError(
                'Options --sso-acct-id and --sso-role-name need --start_url or valid accessToken.')

    if (operation != 'dumpconfig' and options.target_arns != None):
        raise ValueError('Option --target-arns is relevant only for "dumpconfig".')

    if (options.refresh != 'auto' and
            options.accesstoken_cache == None and options.use_cache == False):
        raise ValueError('Option --refresh only usable with --use-cache or --accesstoken-cache.')

    if (options.sso_access_token != None and options.accesstoken_cache != None):
        raise ValueError('Options --sso-access-token and --accesstoken-cache are mutually exclusive.')

    if (options.sso_access_token != None and options.use_cache == True):
        raise ValueError('Options --sso-access-token and --use-cache are mutually exclusive.')

    if (options.use_cache == True and options.accesstoken_cache != None):
        raise ValueError('Options --use-cache and --accesstoken-cache are mutually exclusive.')

    try:
        refresh_value = options.refresh.lower()

        if refresh_value == 'auto':
            options.refresh = 'auto'
        elif refresh_value in ('off', 'false'):
            options.refresh = 'off'
        elif refresh_value in ('on', 'true', 'force'):
            options.refresh = 'force'
        else:
            raise ValueError('Invalid value "%s" for --refresh.' % options.refresh)

    except ValueError as e:
        raise e


    # ----------------------------------------------------------------------------------------------
    # Determine if we need to fetch new accessToken by checking input options...
    # - User provides --start-url, do full SSO login.
    # - User provides --sso-access-token, use provided token.
    # - User provides --accesstoken-cache, read token from specified cache file.
    # - User provides --use-cache, read token from default cache file.
    # ----------------------------------------------------------------------------------------------
    # User provides start url, do full SSO login.
    if (options.start_url != None and
        options.sso_access_token == None and
        options.accesstoken_cache == None):

        # Exception is dumpconfig, where --start-url + --use-cache means "read cache".
        if (operation == 'dumpconfig' and options.use_cache == True):
            options.accesstoken_cache = 'file://' + get_cache_filename()

            if options.refresh == "force":
                options.sso_access_token = do_accesstoken_refresh()
            else:
                options.sso_access_token = get_cached_accesstoken()

        else:
            if (options.sso_region == None):
                raise ValueError('Must provide --sso-region with --start-url.')

            options.sso_access_token = do_sso_login()

    # User provides accessToken, skip SSO login and use that.
    elif (options.sso_access_token != None):

        # accessToken already stored in options.
        pass

    # User requests to read cache file, so use accessToken from the file.
    elif (options.accesstoken_cache != None or options.use_cache == True):

        if options.use_cache == True:
            # A simple way to allow options --use-cache and --accesstoken-cache to coexist.
            options.accesstoken_cache = 'file://' + get_cache_filename()

        if options.refresh == "force":
            options.sso_access_token = do_accesstoken_refresh()
        else:
            options.sso_access_token = get_cached_accesstoken()


    # ----------------------------------------------------------------------------------------------
    # At this point we MAY have new accessToken from one of above.  Now check the operation...
    # - For console, dumpcreds, getcallerid, if we have accessToken, do get_role_credentials()
    # - For dumpconfig, if we don't have accessToken, quit.
    # ----------------------------------------------------------------------------------------------
    # If we get new role credentials they will be filled here.
    role_credentials = {
        'accessKeyId': None,
        'secretAccessKey': None,
        'sessionToken': None
    }

    if operation in ('console', 'dumpcreds', 'getcallerid', 'runas'):

        if (options.sso_access_token != None):
            if (options.sso_acct_id == None or
                options.sso_role_name == None):
                raise ValueError(
                    'Must provide --sso-acct-id and --sso-role-name to get creds with accessToken.')

            role_credentials = get_oidc_role_credentials(options.sso_access_token)

    elif (operation == 'dumpconfig'):

        if (options.sso_access_token == None):
            raise ValueError('Need an OIDC accessToken to proceed with "dumpconfig".')


    # ----------------------------------------------------------------------------------------------
    # Ops start here...
    # ----------------------------------------------------------------------------------------------
    with AWSContextManager(options.aws_profile,
                           role_credentials['accessKeyId'],
                           role_credentials['secretAccessKey'],
                           role_credentials['sessionToken']
                           ) as ctx:

        # We should have credentials by this point, if not:
        if operation in ('console', 'dumpcreds', 'getcallerid', 'runas'):
            credentials = ctx.session.get_credentials()
            if not hasattr(credentials, 'access_key'):
                raise SystemExit(
                    'Cannot find not find any session credentials, unable to continue.')

        # If the user opts for get-session-token, do that next
        if (options.get_session_token == True):
            get_session_token(ctx)

        # If the user opts for get-federation-token, do that next
        if (options.get_federation_token == True):
            get_federation_token(ctx)

        # If the user opts for assume-roles, do that next
        if (options.assume_roles != None):
            assume_roles(ctx)


        if operation == 'console':

            # Using whatever creds are in ctx.session, build the URL to open the console.
            url = construct_federated_url(ctx)

            print(f"Your console signin URL is: {url}")

            copy_url_to_clipboard(url)

            if options.no_browser == False:
                print('Attempting to automatically open browser window for URL...')
                webbrowser.open_new_tab(url)


        elif operation == 'dumpcreds':

            # Using whatever creds are in ctx.session, extract them so we can print.
            credentials = ctx.session.get_credentials()

            dumpcreds = ''

            if str.lower(options.outform) == 'windows':
                dumpcreds = (f'SET AWS_ACCESS_KEY_ID={credentials.access_key}\n' +
                             f'SET AWS_SECRET_ACCESS_KEY={credentials.secret_key}\n' +
                             f'SET AWS_SESSION_TOKEN={credentials.token}')
            elif str.lower(options.outform) == 'powershell':
                dumpcreds = (f'$Env:AWS_ACCESS_KEY_ID={credentials.access_key}\n' +
                             f'$Env:AWS_SECRET_ACCESS_KEY={credentials.secret_key}\n' +
                             f'$Env:AWS_SESSION_TOKEN={credentials.token}')
            else:
                dumpcreds = (f'export AWS_ACCESS_KEY_ID={credentials.access_key}\n' +
                             f'export AWS_SECRET_ACCESS_KEY={credentials.secret_key}\n' +
                             f'export AWS_SESSION_TOKEN={credentials.token}')

            print("# Your session credentials are...\n" + dumpcreds)

            copy_url_to_clipboard(dumpcreds)


        elif operation == 'getcallerid':

            # Using whatever creds are in ctx.session, display the caller identity.
            sts_client = ctx.session.client('sts')

            response = sts_client.get_caller_identity()

            response.pop('ResponseMetadata')
            print(json.dumps(response, indent=4, sort_keys=False, default=str))


        elif operation == 'runas':

            # Copy the current envionment.
            env = os.environ.copy()

            # Using whatever creds are in ctx.session, export them to the shell.
            credentials = ctx.session.get_credentials()

            env_var_set = [{'AWS_ACCESS_KEY_ID': credentials.access_key},
                           {'AWS_SECRET_ACCESS_KEY': credentials.secret_key},
                           {'AWS_SESSION_TOKEN': credentials.token}]

            for pair in env_var_set:
                env.update(pair)

            # If not set, the command will use whatever region is set in current env.
            if options.region != None:
                env.update({'AWS_REGION': options.region})

            command = options.command

            result = subprocess.run(command, shell=True, env=env)

            print('Return code: %s' % result.returncode)


        elif operation == 'importcache':
            import_accesstoken_cache()


        # ------------------------------------------------------------------------------------------
        # Generate a user's AWS config file for SSO login through Identity Center.
        #
        #  The program will open a browser window for you to SSO login.  Afterward, close the tab and hit
        #  return.  The program will build your config and output it to stdout.  To use, add the snip
        #  to your ".aws/config" file.
        # ------------------------------------------------------------------------------------------
        elif operation == 'dumpconfig':

            accessToken = options.sso_access_token
            ssoSessionName = options.sso_session_name
            startURL = options.start_url

            # Create an SSO client
            sso_client = ctx.session.client('sso', region_name=options.sso_region)

            # To add autorefresh support we do a "dummy" operation here...
            refresh_tried = False
            while True:

                try:
                    response = sso_client.list_accounts(
                        accessToken = accessToken,
                        maxResults = 1,
                    )

                except sso_client.exceptions.UnauthorizedException as e:
                    print('Error (%s) %s' % (e.__class__.__name__, e))

                    if options.refresh == 'off':
                        exit(1)

                    if options.accesstoken_cache == None:
                        raise SystemExit('Sorry, no autorefesh available :-(')

                    if refresh_tried == True:
                        print('Look, we already did accessToken refresh and still we get:')
                        raise SystemExit('Error: accessToken not valid: (%s) %s' % (
                            e.__class__.__name__, e))

                    print('Trying auto-refresh...')
                    refresh_tried = True
                    try:
                        accessToken = do_accesstoken_refresh()
                    except Exception as ee:
                        raise SystemExit('Error: accessToken refresh failed: (%s) %s' % (
                            ee.__class__.__name__, ee))

                except Exception as e:
                    raise SystemExit('Error (%s) %s' % (e.__class__.__name__, e))

                else:
                    break


            print('======== ADD THE FOLLOWING TO YOUR .aws/config FILE ========')

            # Create the IdC portal entry...
            print('')
            print('# This is the Identity Center portal entry')
            print('[sso-session %s]' % ssoSessionName)
            print('sso_region = %s' % options.sso_region)
            print(('sso_start_url = %s' % startURL) if (startURL != None)
                  else '# sso_start_url = https://YOUR.START.URL.HERE')
            print('sso_registration_scopes = sso:account:access')
            print('')

            # Build a dict keyed by "profile_name", where each value is a tuple like (accountId, roleName, region).
            sso_profiles = {}

            paginator = sso_client.get_paginator('list_accounts')
            for page in paginator.paginate(accessToken = accessToken):

                for acct in page['accountList']:

                    paginator = sso_client.get_paginator('list_account_roles')
                    for page in paginator.paginate(
                        accessToken = accessToken,
                        accountId = acct['accountId']
                    ):
                        for role in page['roleList']:

                            profile_name = f'{acct["accountName"]}-{role["roleName"]}'
                            sso_profiles.setdefault(profile_name,
                                                    (acct['accountId'], role['roleName'], options.sso_region))

            # Dump all profile entries...
            for k, v in sorted(sso_profiles.items()):
                (accountId, roleName, region) = v
                print('[profile %s]' % k)
                print('sso_session = %s' % ssoSessionName)
                print('sso_account_id = %s' % accountId)
                print('sso_role_name = %s' % roleName)
                if options.region != None:
                    print('region = %s' % options.region)
                else:
                    print('# region = %s' % options.sso_region)
                print('')

            # If user provides these, we can also generate 'assume role' target entries for this source_profile...
            if (options.sso_acct_id != None and
                options.sso_role_name != None and
                options.target_arns != None):

                # Scan the previously generated list to see if we have a matching source profile...
                for k, v in sorted(sso_profiles.items()):
                    (accountId, roleName, region) = v

                    if options.sso_acct_id == accountId and options.sso_role_name == roleName:

                        for role_arn in read_list_fom_input('--target-arns', options.target_arns):

                            arn = parse_arn(role_arn)

                            print('[profile %s-%s]' % (arn['acct_id'], arn['role_name']))
                            print('source_profile = %s' % k)
                            print('role_arn = %s' % role_arn)
                            print('role_session_name = %s' % options.role_sessionname)
                            if options.region != None:
                                print('region = %s' % options.region)
                            else:
                                print('# region = %s' % options.sso_region)
                            print('')



# --------------------------------------------------------------------------------------------------
# Main...
# --------------------------------------------------------------------------------------------------
def main():
    rc = 0

    try:
        # Get loglevel from environment
        try:
            LOGLEVEL = os.environ.get('LOGLEVEL').upper()
        except AttributeError as e:
            LOGLEVEL = 'CRITICAL'

        logging.basicConfig(level=LOGLEVEL)

        rc = run()

    except KeyboardInterrupt:
        print('Killed by keyboard interrupt.')
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)

    except Exception as e:
        print('Error (%s) %s' % (e.__class__.__name__, e))
        rc = 1
        exit(rc)

    return(rc)



if __name__ == '__main__':
    sys.exit(main())
