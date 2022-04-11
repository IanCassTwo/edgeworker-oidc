# OpenID Connect at the Akamai Edge
This EdgeWorker can be used as a sample or starting point of how to perform IDP integration at the Edge using OpenID Connect to the OneLogin IDP.

To be used as sample code. Lots of topics not implemented yet, amongs others:
- Logout
- Other IDP providers (tested with Google)
- More fine-grained authorization (currently allows anyone from the same org)

Consider this as sample code, Work In Progress

## Components
- Identity Provider, for example Google
- Application delivered via Akamai
- Origin with protected content, can be static storage like NetStorage or S3
- EdgeWorker to implement authentication logic
- Proxy to Identity Provider

## EdgeWorker resources
The EdgeWorker currently supports the following resources:
### /.../login?url=redirect-url
Initiate the login process.

Parameters:
- url: Used upon successful login to redirect to the original requested url. Default /
   - Special value: debug_block - the callback will not be performed (give the developer to do the callback locally using the sandbox)
   - Special value: debug_info - instead of redirect detailed information about the response of the callback will be provided.
### /.../callback?code=authorization-code
Used upon succesful authentication at the IDP to request the JWT tokens, create the akamai_token and perform the redirect to the origal requested url.

# Configuration
For the sake of clearity the following example endpoints are used in the documentation and configuration files
1. Application domain
   - Example: application.example.com
   - The EdgeWorker is available via /oidc/
   - The IDP is proxied via /onelogin/
1. IDP domain
   - Example: oauth2.googleapis.com

## IDP provider
The application needs to be configured at the IDP provider. Example for Google:
https://developers.google.com/identity/protocols/oauth2/openid-connect
1. IDP domain
   - Authentication URL - https://accounts.google.com/o/oauth2/v2/auth
   - Token URL - https://oauth2.googleapis.com/token
1. Application Configuration
   - Login URL - https://application.example.com/oidc/login
   - Redirect URL - https://application.example.com/oidc/callback
   - Token URL - https://application.example.com/oidc/token - should proxy to https://oauth2.googleapis.com/token
1. IDP configuration
   - SSO
      - ClientID (OIDC_CLIENTID)
      - Client secret (OIDC_SECRET)

## EdgeWorker
Multiple endpoints are defined in the EdgeWorker and needs to be changed in the responseProvider
1. oidcContext.auth
   - Authentication URL - https://accounts.google.com/o/oauth2/v2/auth

## Property Manager - application
The application involves the EdgeWorker only during login time. When a valid and not-expired token is available access will be granted without involvement of the EdgeWorker.

### Variables
User defined variables are required in order to share the required credentials with the EdgeWorker.
1. OIDC_AKSECRET - The key used to generate the token
1. OIDC_CLIENTID - The client id of the OpenID provider
1. OIDC_SECRET - The secret to be used in combination with the client id 

### Rules
At the application level their needs the following rules:
1. An unprotected path to involve the EdgeWorker
   - IF path matches /oidc/*
      - Edgeworker
1. Protected area's are protected using an Akamai token (using the key as specified in OIDC_AKSECRET). Note, salt should be specified as the domain name for the organization so that you can't use any Google account to log in
   - IF NOT path matches /oidc/*
      - Validate token
      - IF NOT valid token
         - Redirect /oidc/login?url=urlEncode(URL)
1. If path matches /oidc/token
    - Origin = https://oauth2.googleapis.com/token
    - Path overriden to "/token"







