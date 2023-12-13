#!/usr/bin/env python
# -*- coding: UTF-8 -*-

'''
A simple tool to dump session credentials or open the AWS Management Console as a given user identity.

Can get credentials from env, or named config, or SSO login.

(c) Copyright Dave Heller 2023
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
        Name = 'aws-login',      # ditto
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
            RoleSessionName = 'aws-login'
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
    Do the full AWS SSO login and get session credentials for the specified acct and SSO role.
    '''

    # Create an SSO OIDC client
    sso_oidc = boto3.client('sso-oidc', region_name=options.sso_region)

    # Register the client
    client = sso_oidc.register_client(
        clientName = 'aws-login.py',
        clientType ='public'
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
    print()

    return accessToken


def get_oidc_role_credentials(accessToken):
    '''
    Use a provided accessToken to get session credentials for the specified acct and SSO role.
    '''

    # Create an SSO client
    sso_client = boto3.client('sso', region_name=options.sso_region)

    # Get session credentials for an SSO role in an account
    response = sso_client.get_role_credentials(
        accessToken = accessToken,
        accountId = options.sso_acct_id,
        roleName = options.sso_role_name
    )

    # Get the credentials from the JSON response
    role_credentials = response['roleCredentials']

    return role_credentials


def read_list_fom_input(input_name, input_value):

    output_list = []
    payload = ''

    if input_value != None:

        if (input_value == ''):
            raise ValueError('Error: empty value passed to "%s".' % input_name)

        loc = input_value.split('file://')

        if (len(loc) == 1):
            payload = loc[0]

        elif (len(loc) == 2):
            payload = open(loc[1], 'rt').read()

        elif (len(loc) > 2):
            raise ValueError('Error: unable to parse the value passed to "%s".' % input_name)

        try:
            # Valid JSON?
            output_list = json.loads(payload)

        except json.JSONDecodeError:
            # Must be a CSV.
            output_list = ''.join(payload.split()).split(',')

    return output_list


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
# Main...
# --------------------------------------------------------------------------------------------------
def main():

    cmds_usage = '''\nAvailable commands:
    console
    dumpcreds
    dumpconfig
    '''.rstrip()

    usage = 'usage: %prog command [options]\n   ex: %prog create-group --group_name MyGroup\n'
    parser = OptionParser(usage + cmds_usage)
    global options

    parser.add_option('--profile', dest='aws_profile', default=None,
                      help='AWS profile to use')
    parser.add_option('--assume-roles', dest='assume_roles', default=None,
                      help='Chained list of role Arns to assume')
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
                      help='Use OIDC accessToken to get session credentials')
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

    (options, args) = parser.parse_args()

    operation = None

    if len(args) > 0:
        op = args[0].lower()
        if op == 'console':
            operation = op
        elif op == 'dumpcreds':
            operation = op
        elif op == 'dumpconfig':
            operation = op
        else:
            print('Unknown command: %s\n' % op)

    if operation == None:
        parser.print_help()
        exit(1)


    # ----------------------------------------------------------------------------------------------
    # Check input options...
    # ----------------------------------------------------------------------------------------------
    if options.sso_acct_id != None and options.sso_role_name == None:
        print('Option --sso-acct-id is of no use without --sso-role-name.')
        exit(1)
    elif options.sso_role_name != None and options.sso_acct_id == None:
        print('Option --sso-role-name is of no use without --sso-acct-id.')
        exit(1)

    if (operation != 'dumpconfig' and options.target_arns != None):
        print('Option --target-arns is relevant only for "dumpconfig"')
        exit(1)

    # ----------------------------------------------------------------------------------------------
    # If user opts for do_sso_login(), do that first...
    # ----------------------------------------------------------------------------------------------
    role_credentials = {
        'accessKeyId': None,
        'secretAccessKey': None,
        'sessionToken': None
    }

    # If user provides start url, do full sso login...
    if (operation != 'dumpconfig' and options.start_url != None):

        if (options.start_url == None or
            options.sso_region == None or
            options.sso_acct_id == None or
            options.sso_role_name == None):
            print('Must provide --start-url, --sso-region, --sso-acct-id and --sso-role-name to do SSO login.')
            exit(1)

        role_credentials = get_oidc_role_credentials(do_sso_login())

    # If user provides accessToken, get session creds using this token...
    elif (operation != 'dumpconfig' and options.sso_access_token != None):

        if (options.sso_access_token == None or
            options.sso_acct_id == None or
            options.sso_role_name == None):
            print('Must provide --sso-acct-id and --sso-role-name to get creds with accessToken.')
            exit(1)

        role_credentials = get_oidc_role_credentials(options.sso_access_token)


    # ----------------------------------------------------------------------------------------------
    # Ops start here...
    # ----------------------------------------------------------------------------------------------
    with AWSContextManager(options.aws_profile,
                           role_credentials['accessKeyId'],
                           role_credentials['secretAccessKey'],
                           role_credentials['sessionToken']
                           ) as ctx:

        # We should have credentials by this point, if not:
        credentials = ctx.session.get_credentials()
        if not hasattr(credentials, 'access_key'):
            print('Cannot find not find any session credentials, unable continue.')
            exit(1)

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

            # Using whatever creds are in ctx.session, build the URL to open the console...
            url = construct_federated_url(ctx)

            print(f"Your console signin URL is: {url}")

            copy_url_to_clipboard(url)

            if options.no_browser == False:
                print('Attempting to automatically open browser window for URL...')
                webbrowser.open_new_tab(url)


        elif operation == 'dumpcreds':

            dumpcreds = ''
            credentials = ctx.session.get_credentials()

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


        # ------------------------------------------------------------------------------------------
        # Auto generate a user's AWS config file for SSO login through Identity Center.
        #
        #  The program will open a browser window for you to SSO login.  Afterward, close the tab and hit
        #  return.  The program will build your config and output it to stdout.  To use, add the snip
        #  to your ".aws/config" file.
        #
        # ------------------------------------------------------------------------------------------
        elif operation == 'dumpconfig':

            accessToken = ''
            ssoSessionName = options.sso_session_name
            startURL = options.start_url

            # If user provides accessToken here, the intent is is to use it in lieu of full SSO login.
            # User SHOULD additionally provide start URL, but if not we will fill in a placeholder
            if (options.sso_access_token != None):
                accessToken = options.sso_access_token

            else:
                # User MUST provide start url in this case, as we'll need it to get accessToken.
                if (options.start_url == None):
                    print('Must minimally provide --start-url or --sso-access-token to proceed.')
                    exit(1)
                accessToken = do_sso_login()


            print('======== ADD THE FOLLOWING TO YOUR .aws/config FILE ========')

            # Create the IdC portal entry...
            print('')
            print('# This is the Identity Center portal entry')
            print('[sso-session %s]' % ssoSessionName)
            print('sso_region = %s' % options.sso_region)
            print(('sso_start_url = %s' % startURL) if (startURL != None)
                  else '# sso_start_url = https://YOUR.START.URL.HERE')
            print('# sso_registration_scopes = sso:account:access')
            print('')

            # Build a dict keyed by "profile_name", where each value is a tuple like (accountId, roleName, region).
            sso_profiles = {}

            # Create an SSO client
            sso_client = ctx.session.client('sso', region_name=options.sso_region)

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
                print('# region = %s' % region)
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
                            print('role_session_name = %s' % 'aws-login')
                            print('# region = %s' % region)
                            print('')



if __name__ == '__main__':
    rc = 0

    try:
        # Get loglevel from environment
        try:
            LOGLEVEL = os.environ.get('LOGLEVEL').upper()
        except AttributeError as e:
            LOGLEVEL = 'CRITICAL'

        logging.basicConfig(level=LOGLEVEL)

        rc = main()

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

    sys.exit(rc)
