# Overview

A simple tool to open an AWS Console session for any IAM identity you specify (```console```).  You can also dump STS credentials (```dumpcreds```) or do an STS GetCallerIdentity query (```getcallerid```), or run an arbitrary shell command (```runas```) using that identity.

You can use any profile in your ```.aws/config``` or ```.aws/credentials``` file, but you are not limited to your currently defined profiles.  You can specify any IAM identity you have privilege to assume.  You can perform any number of assume-role transitions needed to arrive at your target identity, all in a single operation.

Supports any STS credential source, including AWS Identity Center SSO login and EC2 IMDS.

As a separate feature, the program will dump a ready-to-use ```.aws/config``` file with all your allowed SSO accesses from AWS Identity Center.  This lets you easily generate profiles for your currently assigned access and make changes when new access is assigned.

## Command summary

You can perform any of the following with your acquired IAM identity:

  * ```console``` command - Open an AWS management console session to the acquired identity (opens a browser window).
  * ```dumpcreds``` command - Output STS session credentials for the acquired identity.
  * ```getcallerid``` command - Do an STS get-caller-identity query, showing the acquired identity.
  * ```runas``` command - Run a single shell command using the acquired identity.

You can do the following with AWS Identity Center sign-in or ```accessToken``` from sign-in:

  * ```dumpconfig``` command - Generate profiles for all your currently assigned IdC access.


# Build and install

```
$ pip install setuptools build
$ cd <project directory>
$ python -m build
$ pip install ./dist/aws_login-0.1.0-py3-none-any.whl
```

You will now have the ```aws-login``` executable installed.  If not found, run ```pip show aws-login``` and check the installed Location.  The executable should be installed in the ```./bin``` directory that is the peer of the displayed ```./lib``` directory.  Make sure this directory is in your path.


# Part 1: Commands using an acquired IAM identity

## How it works

1. The program takes a set of *starting credentials*, from the local environment or from SSO login via Identity Center, and optionally does one or more ```--assume-roles``` on top.
2. Using the acquired credentials you can do ```console```, ```dumpcreds```, ```getcallerid``` or```runas``` as described above.

### Starting credentials are from one of the following:

**From your local environment:**

From environment vars:

- Set by env vars ```AWS_ACCESS_KEY_ID``` and ```AWS_SECRET_ACCESS_KEY``` (static credentials)
- Set by env vars ```AWS_ACCESS_KEY_ID```, ```AWS_SECRET_ACCESS_KEY``` and ```AWS_SESSION_TOKEN``` (temporary session credentials)

From profile in AWS ```config``` or ```credentials``` file:

- Set by env var: ```AWS_PROFILE=mySessionProfile```
- Set by command-line option:  ```--profile mySessionProfile```

**From SSO sign-in with AWS Identity Center:**

- Assume the specified account & role by SSO login at ```--start-url```
- Assume the specified account & role using provided ```--sso-access-token```
- Assume the specified account & role using accessToken read from ```--accesstoken-cache``` file, or from internal cache (```--use-cache``` option)

**From EC2 instance:**

- On an EC2 instance, the boto3 libs will automatically fetch starting credentials from IMDSv2.


### Additional assume-role operations are by one of the following:

- User specifies ```--assume-roles``` and passes one or more IAM role Arns to chain through
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

If you don't have a browser installed, you can use the ```--no-browser``` option and paste the generated URL into any browser.  (<span style="color:red">Treat the generated URL as SECRET!!</span>)
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

The following should work on Linux, Mac or Windows WSL:
```
alias get-aws-oidc-accessToken='(cd $HOME/.aws/sso/cache/; jq -r .accessToken < $(ls -t | head -1))'
```

## Dump credentials

Any of the above operations can be run substituting the ```dumpcreds``` command.  This dumps STS session credentials in a format ready to consume on linux, mac, windows or powershell.  Consuming these credentials, you will assume the target identity.
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

Assume the target identity directly:
```
$ source <(aws-login dumpcreds --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole")
```

## Get caller identity

Any of the above operations can be run substituting the ```getcallerid``` command.  This does an STS GetCallerIdentity() query using the acquired identity.  This is good for testing the identity before you use it.

Note this displays the identity you *would* acquire by consuming the credentials, *not* the identity you have currently.  The exception would be calling ```aws-login getcallerid``` with no additional options, which reports your current identity.

## Assuming an identity

Here is an example of how to assume a new identity using ```dumpcreds``` and check your acquired identity with ```getcallerid```:
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
NOTE The above example used an identity acquired from SSO login, but you can do the same with any acquired identity.


## Using "runas"

With ```runas``` you can execute a single shell command under the acquired identity.  This effectively sets ```AWS_ACCESS_KEY_ID```, ```AWS_SECRET_ACCESS_KEY``` and ```AWS_SESSION_TOKEN```  for the duration of the command.

This is useful for running commands with a given identity, without having to create a profile for that identity.

Examples using SSO login:
```
$ aws-login runas --sso-access-token $(get-aws-oidc-accessToken) --sso-acct-id 111111111111 --sso-role-name "PowerUserAccess" --command "aws sts get-caller-identity"

$ aws-login runas --sso-access-token $(get-aws-oidc-accessToken) --sso-acct-id 111111111111 --sso-role-name "PowerUserAccess" --command "aws iam list-roles"

$ aws-login runas --sso-access-token $(get-aws-oidc-accessToken) --sso-acct-id 111111111111 --sso-role-name "PowerUserAccess" --command "aws ec2 describe-instances" --region us-east-2
```
Examples using assume-role:
```
$ aws-login runas --assume-roles "arn:aws:iam::222222222222:role/OperatorRole" --command "aws eks list-clusters" --region us-east-2

$ aws-login runas --profile "myStartingRole" --assume-roles "arn:aws:iam::222222222222:role/OperatorRole" --command "MyProgramUsingAwsApi"
```
You can run multiple commands in single invocation, for example:
```
$ aws-login runas --use-cache --sso-acct-id 111111111111 --sso-role-name "PowerUserAccess" --command '
rolename=$(aws iam list-roles | jq -r ".Roles[] | select(.RoleName | startswith(\"AppDeveloperRole-\")) | .RoleName")
test -z "$rolename" && exit 1
echo "$rolename"
aws iam tag-role  --role-name "$rolename" --tags "Key=OwnedBy, Value=Development"
aws iam list-role-tags --role-name "$rolename"
'
```

## Using accessToken caching and auto-refresh

In all operations so far where we obtained an identity by SSO login, we've run the program in a "stateless" mode, with no caching of the acquired SSO accessToken.  So on subsequent operations we need to pass ```--start-url``` and do the full SSO login again, or provide some ```--sso-access-token``` cached elsewhere, like from the ```aws sso login``` command.

With caching and auto-refresh support, the program will store the accessToken obtained from the initial SSO login.  You can then use this accessToken for additional operations without having to do the SSO login again.  When the cached accessToken is expired the program will attempt to refresh it, if the token is of refreshable type ("refreshToken" is present in the cache).  If the token is not refreshable you get the full active lifetime of "accessToken".  If it is refreshable you get the full lifetime of "refreshToken", which is typically longer.  Once the token is no longer refreshable, then you have to do SSO login again.  (This is similar to ```aws sso``` native caching.)

You can also consume an external cache file, like the one stored by ```aws sso login```, by passing the file path to ```--accesstoken-cache```.

You can also import an external cache file with the ```importcache``` command.  This brings the file to ```aws-login```'s internal cache and uses it as if it were created by the program itself.  If you are already signed by ```aws sso login```, this is often the easiest way.  When your accessToken is no longer refreshable, simply sign in with ```aws sso login``` and ```importcache``` again.

### Examples

Do full AWS SSO login and *store* the acquired accessToken.
```
$ aws-login console --use-cache --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```
*Consume* cached accessToken.  Automatically attempt refresh if expired and store the new accessToken upon successful refresh:
```
$ aws-login console --use-cache --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```
Consume external cache specified by ```--accesstoken-cache```.  (Auto-refresh is still enabled but the updated token will not be re-stored.)
```
$ alias get-aws-oidc-accessToken-cache='ls -t $HOME/.aws/sso/cache/*.json | head -1'
$ aws-login console --accesstoken-cache file://$(get-aws-oidc-accessToken-cache) --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```
*Import* an external file to internal cache.  Must be a valid JSON cache file.
```
$ aws-login importcache --accesstoken-cache file://$(get-aws-oidc-accessToken-cache)
```
NOTE: The above examples use ```console``` but you can alternately pass ```dumpcreds```, ```getcallerid``` or ```runas``` instead.

---

## Using "--credential-helper"

The challenge with ```runas``` (or assuming identity from ```dumpcreds``` as shown above) is that it only fetches one set of STS credentials at a time.  This makes them good for quick tasks, but if you have any job running longer than your STS token lifetime it will fail.

To run with "autorefresh" you can use ```credential_process``` in a profile entry in your ```.aws/config``` or ```.aws/credentials``` file, like this:
```
[profile blah]
credential_process = aws-login dumpcreds --credential-helper ...
```
where the remaining command line is *any* working ```dumpcreds``` command.  Simply add the ```--credential-helper``` to output in the required format.

You can then consume your credentials like:
```
aws sts --get-caller-identity --profile blah
```
and the STS credentials should be refreshed as long as the command is able to do so.

(NOTE: Usually it's easier to set up a standard AWS profile than using ```aws-login``` in this manner.  But it it may be useful for automation, or for programs that don't support newer AWS profile types.)


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

**NOTE:** Although you provide ```--sso-region```, the region of the Identity Center instance, the program does not know what region you want to use for each profile entry.  By default it adds a region pointing the same as sso-region, but this entry is commented out.  If you want to use a different region you can pass the ```--region``` option, which will set the region for all entries.

Unfortunately there is no way to set a per-entry value.  If you need to set a different regions for different profiles, edit the file accordingly.
