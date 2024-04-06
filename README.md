# Overview

A simple tool to start an AWS Console session, dump STS credentials, or do an STS GetCallerIdentity() query for any identity the user selects.  Performs any number of additional assume-role transitions.  Supports any credential source, including SSO login from AWS Identity Center.

As a separate feature, the program will dump a ready-to-use AWS "config" file with all your allowed SSO accesses from AWS Identity Center.


# Build and install

```
$ pip install setuptools build
$ cd <project directory>
$ python -m build
$ pip install ./dist/aws_sso_admin_tools-0.1.0-py3-none-any.whl
```

You will now have the ```aws-login``` executable installed.  If not found, run ```pip show aws-login``` and check the installed "Location".  The executable should be installed in the ```./bin``` directory that is the peer of the displayed ```./lib``` directory.  Make sure this directory is in your path.


# Part 1: Using the program open AWS console, get session credentials (STS credentials) or do STS getcallerid

## How it works

1. The program takes a set of *starting credentials*, from environment or from SSO login, and optionally does one or more ```--assume-roles``` on top.
2. Using the acquired credentials, take one of the following actions:
  * ```console``` command - Open an AWS management console session to the acquired identity.
  * ```dumpcreds``` command - Output STS session credentials for the acquired identity.
  * ```getcallerid``` command - Do an STS get-caller-identity query, showing the acquired identity.
 
### Starting credentials are from one of the following sources:

**From your local environment:**

From environment vars:

- Set by env vars ```AWS_ACCESS_KEY_ID``` and ```AWS_SECRET_ACCESS_KEY``` (static credentials)
- Set by env vars ```AWS_ACCESS_KEY_ID```, ```AWS_SECRET_ACCESS_KEY``` and ```AWS_SESSION_TOKEN``` (temporary session credentials)

From profile in AWS ```config``` or ```credentials``` file:

- Set by env var: ```AWS_PROFILE=mySessionProfile```
- Set by command-line option:  ```--profile mySessionProfile```

**From AWS SSO login:**

- Assume the specified account & role following SSO login at provided ```--start-url```
- Assume the specified account & role using provided ```--sso-access-token```
- Assume the specified account & role using accessToken read from ```--accesstoken-cache``` file, or from internal cache (```--use-cache``` option)

**From EC2 instance:**

- On an EC2 instance, the boto3 libs will automatically fetch credentials from IMDSv2.  You should not have to set any AWS config at all.


### Additional assume-role operations are by one of the following methods:

- User specifies ```--assume-roles``` and passes one or more IAM role Arns to chain to
- User specifies ```--get-session-token``` (applies only to static creds)
- User specifies ```--get-federation-token``` (applies only to static creds / required for console access by IAM user)


## Examples

### Using environmental credentials

Open console with creds from environment or from specified profile:
```
$ aws-login console
$ aws-login console --profile "mySessionProfile"
```

Do one or more additional role-chains before opening console:
```
$ aws-login console --assume-roles "arn:aws:iam::222222222222:role/TargetRole"
$ aws-login console --assume-roles "arn:aws:iam::111111111111:role/IntermediateRole, arn:aws:iam::222222222222:role/TargetRole"
```

Same as above but specifying starting profile:
```
$ aws-login console --profile "myStartingRole" --assume-roles "arn:aws:iam::222222222222:role/TargetRole"
$ aws-login console --profile "myStartingRole" --assume-roles "arn:aws:iam::111111111111:role/IntermediateRole, arn:aws:iam::222222222222:role/TargetRole"
```

### Using AWS SSO login

Do full AWS SSO login and open console to the account/role specified.  Role must be authorized for the user in AWS Identity Center.  Opens browser window for login.
```
$ aws-login console --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```

If you don't have a browser installed locally you can use ```--no-browser``` and copy and paste the URL.
```
$ aws-login console --no-browser --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```

Same, but use provided AWS OIDC ```accessToken``` instead of doing full SSO login.  For example, you can pass an accessToken fetched by ```aws sso login```.
```
$ aws-login console --sso-access-token $(get-aws-oidc-accessToken) --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```

Do one or more additional role-chains before opening console:
```
$ aws-login console --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_SourceRole" --assume-roles "arn:aws:iam::222222222222:role/TargetRole"

$ aws-login console --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_SourceRole" --assume-roles "arn:aws:iam::111111111111:role/IntermediateRole, arn:aws:iam::222222222222:role/TargetRole"
```

Same, using AWS OIDC ```accessToken```:
```
$ aws-login console --sso-access-token $(get-aws-oidc-accessToken) --sso-acct-id 111111111111 --sso-role-name "SSO_SourceRole" --assume-roles "arn:aws:iam::222222222222:role/TargetRole"

$ aws-login console --sso-access-token $(get-aws-oidc-accessToken) --sso-acct-id 111111111111 --sso-role-name "SSO_SourceRole" --assume-roles "arn:aws:iam::111111111111:role/IntermediateRole, arn:aws:iam::222222222222:role/TargetRole"
```

On mac and linux, accessToken can be got by:
```
alias get-aws-oidc-accessToken='(cd $HOME/.aws/sso/cache/; jq -r .accessToken < $(ls -t | head -1))'
```

## Dump credentials

Any of the above commands can be run substituting "dumpcreds" for "console".  This dumps STS session credentials in a format ready to consume on linux, mac, windows or powershell.  Consuming these credentials, you will assume the target identity.
```
$ aws-login dumpcreds
$ aws-login dumpcreds --profile "mySessionProfile"

$ aws-login dumpcreds --outform linux
$ aws-login dumpcreds --outform mac
$ aws-login dumpcreds --outform windows
$ aws-login dumpcreds --outform powershell
```

Example:
```
$ aws-login dumpcreds --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
# Your session credentials are...
export AWS_ACCESS_KEY_ID=ASIARSWJKK4662QX2I64
export AWS_SECRET_ACCESS_KEY=rMkZ1wAz3cXYkBLiL9xllh1zOLzVxq4Pwy..
export AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEBkaCXVzLWVhc3QtMSJIMEYCIQDf1rBRloTAf...
```

Consume the target identity directly:
```
$ source <(aws-login dumpcreds --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole")
```

## Get caller identity

Any of the above commands can be run substituting "getcallerid" for "console".  This does an STS GetCallerIdentity() query using the acquired target credentials.  Note this displays the identity you *would* acquire by consuming the credentials, *not* the identity you have currently.  The exception would be calling ```aws-login getcallerid``` with no additional options; in this case, the reported identity will reflect the one you currently have.

Here is an example of how to acquire a new identity using ```dumpcreds``` and check your acquired or current identity with ```getcallerid```:
```
$ aws-login getcallerid
Cannot find not find any session credentials, unable to continue.

$ aws-login getcallerid --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
{
    "UserId": "AROARS2QX222XXJREUNB6:ima.user@my.org",
    "Account": "111111111111",
    "Arn": "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_SSO_TargetRole_0e123456789abcde/ima.user@my.org"
}

$ source <(aws-login dumpcreds --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole")

$ aws-login getcallerid
{
    "UserId": "AROARS2QX222XXJREUNB6:ima.user@my.org",
    "Account": "111111111111",
    "Arn": "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_SSO_TargetRole_0e123456789abcde/ima.user@my.org"
}

$ unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

$ aws-login getcallerid
Cannot find not find any session credentials, unable to continue.
```
The above example used an identity acquired from SSO login, but we can do the same using an identity from environment, doing on or more ```--assume-role``` on top.

NOTE: In the above example we did the SSO login twice, passing```--start-url``` to both commands.  We could instead pass a cached accessToken using ```--sso-access-token```, or read the accessToken from internal cache with the ```--use-cache``` option, covered next.

## Using accessToken caching and auto-refresh

In all operations so far where we obtained an identity by SSO login, we've run the program in a "stateless" mode, with no caching of the acquired SSO accessToken.  So on subsequent operations we need to pass ```--start-url``` and do the full SSO login again, or provide some ```--sso-access-token``` cached elsewhere, like from the ```aws sso login``` command.

With caching and auto-refresh support, the program will store the accessToken obtained from the initial SSO login.  You can then use this accessToken for additional operations without having to do the SSO login again.  When the cached accessToken is expired the program will attempt to refresh it, if the token is of refreshable type ("refreshToken" is present in the cache).  If the token is not refreshable you get the full active lifetime of "accessToken".  If it is refreshable you get the full lifetime of "refreshToken", which is typically longer.  Once the token is no longer refreshable, then you have to do SSO login again.

You can also consume an external cache file, like the one stored by ```aws sso login```, by passing the file path to ```--accesstoken-cache```.  You can also ```--import``` this file to internal cache and use it as if it were created by the program initially.

**Caching and auto-refresh examples:**

Do full AWS SSO login and store the acquired accessToken.
```
$ aws-login console --use-cache --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```
Same as above but request non-refreshable token (don't pass "scopes" in the register client call).
```
$ aws-login console --use-cache --nrt --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```
Consume cached accessToken.  Automatically attempt refresh if expired and store the new accessToken upon successful refresh:
```
$ aws-login console --use-cache --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```
Consume external cache specified by ```--accesstoken-cache```.  (Auto-refresh is still enabled but the updated token will not be re-stored.)
```
$ alias get-aws-oidc-accessToken-cache='ls -t $HOME/.aws/sso/cache/*.json | head -1'
$ aws-login console --accesstoken-cache file://$(get-aws-oidc-accessToken-cache) --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```
Import an external file to internal cache.  Must be a valid JSON cache file.
```
$ aws-login importcache --accesstoken-cache file://$(get-aws-oidc-accessToken-cache)
```
You can additionally pass a ```--refresh``` option that accepts the values "on", "off" or "auto".  Auto is the default.  Passing ```--refresh=on``` forces a refresh attempt even if accessToken is not expired, while ```--refresh=off``` prevents auto-refresh.

NOTE: The above examples use "console" but you can alternately pass "dumpcreds" or "getcallerid" instead.


# Part 2: Using the program to export AWS config

## How it works

Starting with an AWS SSO login, the program discovers all SSO roles and accounts assigned to you by AWS Identity Center and outputs the corresponding entries for your ```.aws/config``` file.

Note this works **exclusively** with AWS SSO login.  You either provide ```--start-url```, which will require you to perform the full SSO login, or ```--sso-access-token```, or ```--use-cache``` to use internal cache, or ```--accesstoken-cache``` to use external cache.  Even in the cases where you use a cached accessToken you should **still** pass ```--start-url```, as the value is used to build your ```.aws/config``` output.  If you don't provide it here you will just have to edit the file later to add it.


## Examples (dumpconfig)

Generate the file from full SSO login.  Opens browser window for login.
```
$ aws-login dumpconfig --start-url "https://d-987654321d.awsapps.com/start" --sso-session-name "my-sso" --sso-region "us-east-1"
```

Use a cached accessToken generated externally, like from ```aws sso login```.  You don't have to do full SSO login, but, you should still provide the other options to ensure the correct values are written to your file.
```
$ aws-login dumpconfig --sso-access-token $(get-aws-oidc-accessToken) --start-url "https://d-987654321d.awsapps.com/start" --sso-session-name "my-sso" --sso-region "us-east-1"
```

Use accessToken from internal cache.
```
$ aws-login dumpconfig --use-cache --start-url "https://d-987654321d.awsapps.com/start" --sso-session-name "my-sso" --sso-region "us-east-1"
```

Output will be like:
```
# This is your Identity Center portal entry...
[sso-session my-sso]
sso_region = us-east-1
sso_start_url = https://d-987654321d.awsapps.com/start

# Profiles for your discovered access...
[profile my-acct-1-AdministratorAccess]
sso_session = my-sso
sso_account_id = 111111111111
sso_role_name = AdministratorAccess
#region = us-east-1

[profile my-acct-2-ReadOnlyAccess]
sso_session = my-sso
sso_account_id = 222222222222
sso_role_name = ReadOnlyAccess
#region = us-east-1
```

**NOTE:** Although you provide ```--sso-region```, the region of the Identity Center instance, the program does not know what region you want to use for each profile entry.  By default it adds a region pointing the same as sso-region, but this entry is commented out.  If you want to the set region for a profile, edit the file accordingly.

