# Overview

A simple tool to open an AWS Console session or dump session credentials for any identity the user selects.  Supports any credential source, including AWS Identity Center.

As a separate feature, the program will dump a ready-to-use AWS "config" file with all your allowed SSO accesses from AWS Identity Center.


# Build and install

```
$ pip install setuptools build
$ cd <project directory>
$ python -m build
$ pip install ./dist/aws_sso_admin_tools-0.1.0-py3-none-any.whl
```

You will now have the ```aws-login``` executable installed.  If not found, run ```pip show aws-login``` and check the installed "Location".  The executable should be installed in the ```./bin``` directory that is the peer of the displayed ```./lib``` directory.  Make sure this directory is in your path.


# Part 1: Using the program open AWS console or dumpcreds

## How it works

1. The program takes a set of *starting credentials* and optionally does one or more ```--assume-roles``` on top.
2. Using what credentials are arrived at, either "dumpcreds" or open the AWS management console.

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

**From EC2 instance:**

- On an EC2 instance, the boto3 libs will automatically fetch credentials from IMDSv2.  You should not have to set any AWS config at all.


### Additional assume-role operations are by one of the following methods:

- User specifies ```--assume-roles``` and passes one or more IAM role Arns to chain to
- User specifies ```--get-session-token``` (applies only to static creds)
- User specifies ```--get-federation-token``` (applies only to static creds / required for console access by IAM user)


## Examples

### Using environmental credentials

Open console with creds from environment or specified by cmdline option:
```
$ aws-login console
$ aws-login console --profile "mySessionProfile"
```

Additionally do one or more role-chains before opening console:
```
$ aws-login console --assume-roles "arn:aws:iam::222222222222:role/TargetRole"
$ aws-login console --assume-roles "arn:aws:iam::111111111111:role/IntermediateRole, arn:aws:iam::222222222222:role/TargetRole"
```

Same as above but specifying starting role with cmdline option:
```
$ aws-login console --profile "myStartingRole" --assume-roles "arn:aws:iam::222222222222:role/TargetRole"
$ aws-login console --profile "myStartingRole" --assume-roles "arn:aws:iam::111111111111:role/IntermediateRole, arn:aws:iam::222222222222:role/TargetRole"
```

### Using AWS SSO login

Do full AWS SSO login and open console to the account/role specified.  Role must be authorized for the user in AWS Identity Center.  Opens browser window for login.
```
$ aws-login console --no-browser --start-url "https://d-987654321d.awsapps.com/start" --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```

Same, but use provided AWS OIDC ```accessToken``` instead of doing full SSO login.  Typically this token is got by doing ```aws sso login```.  (See "aws sso get-role-credentials" for details.)
```
$ aws-login console --sso-access-token $(get-aws-oidc-accessToken) --sso-acct-id 111111111111 --sso-role-name "SSO_TargetRole"
```

Additionally do one or more role-chains before opening console:
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

Any of the above commands can be run substituting "dumpcreds" for "console".  This dumps ```AWS_ACCESS_KEY_ID```, ```AWS_SECRET_ACCESS_KEY``` and ```AWS_SESSION_TOKEN``` in a format ready for linux, mac, windows or powershell.
```
$ aws-login dumpcreds
$ aws-login dumpcreds --profile "mySessionProfile"

$ aws-login dumpcreds --outform linux
$ aws-login dumpcreds --outform mac
$ aws-login dumpcreds --outform windows
$ aws-login dumpcreds --outform powershell

...
```

# Part 2: Using the program to export AWS config

## How it works

Starting with an AWS SSO login, the program discovers all SSO roles and accounts assigned to you by AWS Identity Center and outputs the corresponding entries for your ```.aws/config``` file.

Note that this operation works **exclusively** with AWS SSO login.  You either provide ```--start-url```, which will require you to perform the full SSO login, or ```--sso-access-token```, which will enable the program based on a previous SSO login.  Even in the latter case you should still provide ```--start-url```, as the value is needed to build your output.  If you don't provide it here you will just have to edit the file later to add it.


## Examples (dumpconfig)

Generate the file from full SSO login.  Opens browser window for login.
```
$ aws-login dumpconfig --start-url "https://d-987654321d.awsapps.com/start" --sso-session-name "my-sso" --sso-region "us-east-1"
```

Use an accessToken from a previous login to generate the file.  Saves having to do the full SSO login; however, you should still provide the other options to ensure the correct values are written to your file.
```
$ aws-login dumpconfig --sso-access-token $(get-aws-oidc-accessToken) --start-url "https://d-987654321d.awsapps.com/start" --sso-session-name "my-sso" --sso-region "us-east-1"
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

