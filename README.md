# okta_aws_cred_helper

OKTA AWS credential helper.

Currently it only works on Mac. As it is pure python, welcome to extend it for other platforms.

# Install

```

```

# Initialize

Preparation:

1. You need to know Okta AWS application sso URL. It should be like https://domain.okta.com/app/amazon_aws/`<app-id>`/sso/saml.
2. You already have your email/password/google 2Fa set up.
3. During the process, we will reset the Okta Google 2FA code. You will need a QR code scanner application (besides Google 2FA app) so it can read the TOTP code. An useful application can be: https://play.google.com/store/apps/details?id=com.tohsoft.qrcode.pro

## Read your TOTP code

Login to your Okta Account and reset your 2FA code. When you are resetting, while the QR code still displays, use the QR code scanner to decode the QR code, which will be like

`otpauth://totp/xxx.okta.com:<your-email>?secret=<totp-code>&issuer=xxx.okta.com`

Mark the totp code down and you will use it later.


## Initialize credentials

Execute

```
okta-aws-cred-helper init
```

Follow the questions and input your answers. **You will be asked for sso_url, okta username(email), okta password, totp code (you previously marked down). Note whatever you have input will be echo back to the screen. Pleae keep alert from peeping.**

**As this app uses MacOS keychain to store the above secret information, you will be prompt that your current python executor wants to use your credentials. It is ideal to `always allow` python process.**

## Update your `~/.aws/credentials` file

Execute
```
okta-aws-cred-helper init
```

This command will modify your `~/.aws/credentials` for the new credentials derived from okta. The credentials from Okta will be defined as profiles with name starting with `okta-`. 

Note existing credentials in `~/.aws/credentials` with profile name not starting with `okta-` will be intact.

After executing this command, simply check the content of `~/.aws/credentials` to get familiar with what roles OKTA has allowed you to assume to. You can also configure other personal profiles to source from these `okta-` profiles.

## Caching

This process uses directory `~/.aws/okta-aws` as temporary credential caches.

## Improve

The following items are in the view:

- Support windows
- Support linux(ubuntu)
- add a easy role assumption support
- Allow signing Login URLs (working with [awslogin](https://github.com/cheney-yan/awslogin))
