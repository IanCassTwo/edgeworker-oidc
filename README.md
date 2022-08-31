# OpenID Connect at the Akamai Edge

**DISCLAIMER: This code is designed to be used as an example only. No guarantees are made that it's fit for purpose. It's not production ready and should not be used to protect critical resources**

This EdgeWorker is designed to protect an Akamaized site using OpenID Connect (OIDC) in combination with Akamai Token Authentication. The Akamai Authentication token is presented as a cookie and is created upon successful authentication by your IdP. The first time you access, you'd expect to follow the "Invalid Token" flow to log in, then your access would continue unhindered until the token expires.

The two scenarios are provided here for [centralized](/IanCassTwo/edgeworker-oidc/tree/main/centralized) or [distributed](/IanCassTwo/edgeworker-oidc/tree/main/distributed) login. The centralized scenario will allow you to have a single point of login for all protected sites on your domain whilst the distributed scenario will require you to log in to each site individually. For most applications, you'll probably want to choose the centralized option
