# okta_aws_cred_helper

OKTA AWS credential helper.

You you only need the following steps to setup your aws credentials file derived from Okta automatically. Procedures are
```
okta-aws-cred-helper init
okta-aws-cred-helper refresh

# then you are ready to go.
AWS_PROFILE=okta-role aws s3 ls
# If you need to know what profiles are available to you, you need to check your aws credentials file, i.e. ~/.aws/credentials

# when your DevSecOps made change on permissions, you need to refresh your local aws credentials file to pick up the change.
okta-aws-cred-helper refresh
```

# Install

```
pip install okta-aws-credential-helper
```

# Initialize

Preparation:

1. You need to know Okta AWS application sso URL. It should be like https://domain.okta.com/app/amazon_aws/`app-id`/sso/saml.
2. You already have your email/password/google 2Fa set up.
3. During the process, we will reset the Okta Google 2FA code. You will need a QR code scanner application (besides Google 2FA app) so it can read the TOTP code. An useful application can be: https://play.google.com/store/apps/details?id=com.tohsoft.qrcode.pro

## Read your TOTP code

Login to your Okta Account and reset your 2FA code. When you are resetting, while the QR code still displays, use the QR code scanner to decode the QR code, which will be like

`otpauth://totp/xxx.okta.com:<your-email>?secret=<totp-code>&issuer=xxx.okta.com`

Mark the totp code down and you will use it later.


## Initialize okta credentials

Execute

```
okta-aws-cred-helper init
```

Follow the questions and input your answers. **You will be asked for sso_url, okta username(email), okta password, totp code (you previously marked down). Note whatever you have input will be echo back to the screen. Please keep alert from peeping.**


### review your okta credentials settings

**NOTE** your okta credentials settings are stored in file `~/.aws/okta-aws/settings.json`. Keep it secret. You can also edit this file directly later instead of running `okta-aws-cred-helper init` command.

Once initialized, the file should be like
```
{
  "sso_url": "https://domain.okta.com/app/amazon_aws/aaaaabbbbbcccccDDDDD/sso/saml",
  "region": "ap-southeast-2",
  "user_name": "name@email.com.au",
  "password": "<password>",
  "google_2fa_totp": "<totp code>"
}

```

## Automatically set your `~/.aws/credentials` file

Execute
```
okta-aws-cred-helper refresh
```

This command will modify your `~/.aws/credentials` for the new credentials derived from okta. The credentials from Okta will be defined as profiles with name starting with `okta-`. 

Note existing credentials in `~/.aws/credentials` with profile name not starting with `okta-` will be intact.

After executing this command, simply check the content of `~/.aws/credentials` to get familiar with what roles OKTA has allowed you to assume to. You can also configure other personal profiles to source from these `okta-` profiles.

## Caching

This process uses directory `~/.aws/okta-aws` as temporary credential caches.

## Refreshing

This tool automatically refreshes the credentials behind the scene for you.

## Speed

While refreshing credentials, you may feel your aws tools (boto scripts or awscli) freeze for several seconds. This usually happens at the edge of every 30 seconds. When this tool sense it is close to the end of each 30 seconds, it will wait until this 30 second window pass, to avoid the google 2FA authentication failure caused by network delay or time in-synchronization.

## Improve

The following items are in the view:

- Use more secure store.
- Test on windows
- Test on linux(ubuntu)
- add a easy role assumption support
- Allow signing Login URLs (working with [awslogin](https://github.com/cheney-yan/awslogin))
- Package properly and add testing

Contribution welcome..
