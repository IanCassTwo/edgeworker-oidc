/*
(c) Copyright 2021 Akamai Technologies, Inc. Licensed under Apache 2 license.

Version: 1.1
Purpose:  OpenID Connect login  verification at the edge

*/
/// <reference types="akamai-edgeworkers"/>
import { httpRequest } from 'http-request';
import { createResponse } from 'create-response';
import URLSearchParams from 'url-search-params';
import { Cookies, SetCookie } from 'cookies';
import { crypto } from 'crypto';
import { base64url } from 'encoding';
import { EdgeAuth } from "auth/edgeauth.js";


// Utilities - randomstring
function randomString(len) {
  // Output is base 64, ratio is 3/4
  const lenInBytes = Math.ceil(len * 3 / 4);
  let array = new Uint8Array(lenInBytes);
  crypto.getRandomValues(array);
  let s = base64url.encode(array);
  return s.substring(0, len);
}

// Create a cookie in one line
function newCookie(name, val, path) {
  var c = new SetCookie();
  c.name = name;
  c.value = val;
  c.path = path;
  c.secure = true;
  c.httpOnly = true; // Hide auth cookies from client-side JS
  return c;
}

// Unpack the jwt - note: we should verify the signature (not possible in edgeworkers and as we request the token directly we can skip that step)
function jwt2json(s) {
  var r = {};
  try {
    var a = s.split('.');
    r.header = JSON.parse(base64url.decode(a[0], "String"));
    r.payload = JSON.parse(base64url.decode(a[1], "String"));
    r.signature = a[2];
  } catch (e) {
    r.error = e.toString();
  }
  return r;
}

// Auth flow, step 1: Initiate the login by redirection to the login endpoint and storing the login mode
async function oidcLogin(oidcContext, request) {
  let params = new URLSearchParams(request.query);
  let cookies = [];

  // Setup redirect URL
  let redirectUrl = params.get('url');
  if (redirectUrl && isValidRedirectUrl(oidcContext, redirectUrl)) {
    cookies.push(newCookie(oidcContext.redirectUrlCookieName, redirectUrl, oidcContext.basedir).toHeader());
  }
  // Generate and store a nonce
  const nonce = randomString(8);
  cookies.push(newCookie(oidcContext.nonceCookieName, nonce, oidcContext.basedir).toHeader());
  // Generate and store a state
  const state = randomString(8);
  cookies.push(newCookie(oidcContext.stateCookieName, state, oidcContext.basedir).toHeader());

  // Parameters for Identity Provider auth request
  let idpParams = new URLSearchParams({
    client_id: oidcContext.clientId,
    nonce,
    state,
    redirect_uri: oidcContext.redirect,
    response_type: "code",
    scope: oidcContext.scope,
  });

  // Redirect to IDP auth, while setting cookies
  return Promise.resolve(createResponse(
    302,
    {
      location: `${oidcContext.auth}?${idpParams}`,
      "set-cookie": cookies,
    },
    '')
  );
}

function isValidRedirectUrl(oidcContext, redirectUrl) {
  // reject invalid arg
  if (typeof redirectUrl !== 'string')
    return false;
  // debug features
  if (/debug_[a-z]+/.test(redirectUrl))
    return true;
  // allow root on same domain
  if (redirectUrl === "/")
    return true;
  if (oidcContext.domain) {
    // allow root domain and subdomains
    const regexEscapedDomain = oidcContext.domain.replaceAll(".", "\\.");
    const domainValidator = new RegExp(`^https:\/\/([-a-z0-9]+\.)?${regexEscapedDomain}/`, "i");
    return domainValidator.test(redirectUrl);
  } else {
    // allow only current domain
    const regexEscapedDomain = oidcContext.incomingHost.domain.replaceAll(".", "\\.");
    const domainValidator = new RegExp(`^https:\/\/${regexEscapedDomain}/`, "i");
    return domainValidator.test(redirectUrl);
  }
}

// Auth flow, step 2: Callback
// Request parameter: code - code to be used to fetch the token from the idp
// Cookie parameter: loginUrl - redirect url, debug_block (no retrieval), debug_info (collect response info)
async function oidcCallback(oidcContext, request) {
  var params = new URLSearchParams(request.query);
  var cookies = new Cookies(request.getHeader('Cookie'));
  var code = params.get("code");
  var redirectUrl = cookies.get(oidcContext.redirectUrlCookieName) || "/";
  var newCookies = [];
  var failureContent = {};
  var failureStatus = 400;

  if (isValidRedirectUrl(oidcContext, redirectUrl) && code && redirectUrl !== 'debug_block') {
    const state = cookies.get(oidcContext.stateCookieName);
    if (!state || params.get("state") !== state)
      return Promise.resolve(createResponse(403, {}, 'State failed'));

    // Retrieve tokens for the code as passed in
    const tokenParams = new URLSearchParams({
      "grant_type": "authorization_code",
      redirect_uri: oidcContext.redirect,
      code,
      client_id: oidcContext.clientId,
      client_secret: oidcContext.clientSecret
    });
    const tokenResponse = await httpRequest(`${oidcContext.basedir}token`, {
      method: "POST",
      headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
      body: tokenParams.toString()
    });

    if (tokenResponse.ok && redirectUrl != 'debug_break') {
      const tokenResult = await tokenResponse.json();

      const jwtId = jwt2json(tokenResult.id_token);
      tokenResult.id_decode = jwtId;

      const nonce = cookies.get(oidcContext.nonceCookieName);
      if (!(jwtId && jwtId.payload && jwtId.payload.nonce && jwtId.payload.nonce === nonce))
        return Promise.resolve(createResponse(403, {}, 'Nonce failed'));

      // Set cookie: Access token
      // newCookies.push(newCookie('access_token', tokenResult.access_token, '/').toHeader());

      // Create the Akamai token
      var token_start_time = Math.trunc(Date.now() / 1000);
      var acl = ["/*"];
      var ea = new EdgeAuth({
        key: oidcContext.akamaiSecret,
        startTime: token_start_time,
        windowSeconds: tokenResult.expires_in,
        // If you configured salt in Auth Token 2.0 Behavior, re-use value here
        // salt: jwtId.payload.hd,
        // If you want token to carry information, add it to its payload
        // payload: jwtId.payload.email,
        escapeEarly: true,
      });
      let akamaiToken = await ea.generateACLToken(acl);

      let tokenCookie = newCookie(oidcContext.tokenCookieName, akamaiToken, '/');
      tokenCookie.maxAge = tokenResult.expires_in;
      if (oidcContext.domain) {
        tokenCookie.domain = oidcContext.domain;
      }
      newCookies.push(tokenCookie.toHeader());

      // Redirect if we can
      if (redirectUrl !== "debug_info") {
        return Promise.resolve(createResponse(
          302,
          {
            'Set-Cookie': newCookies,
            'Location': [redirectUrl]
          },
          '')
        );
      }

      var jwtAccess = jwt2json(tokenResult.access_token);
      tokenResult.access_decode = jwtAccess;

      //Details send back
      return Promise.resolve(createResponse(
        tokenResponse.status,
        {
          'Set-Cookie': newCookies
        },
        JSON.stringify(tokenResult))
      );
    } else {
      // not tokenResponse.ok, use text instead of JSON as the response is not always JSON
      var x = await tokenResponse.text();
      try {
        failureContent = JSON.parse(x);
        failureContent.url = redirectUrl;
      } catch (err) {
        failureContent.error = "callback_failure";
        failureStatus = tokenResponse.status;
        failureContent.description = "callback received indicates error";
        failureContent.details = x;
        failureContent.path = `${oidcContext.basedir}token`
        failureContent.params = tokenParams;
      }
    }
  } else { // no code given or debug_block requested
    failureContent.error = "precondition";
    failureContent.description = `callback request not initiated, redirect-url:${redirectUrl}, query:${request.query}`;
  }

  // Response for failures
  return Promise.resolve(
    createResponse(failureStatus, { 'content-type': ['application/json'] }, JSON.stringify(failureContent)));
}

function oidcLogout(oidcContext, request) {
  const emptyTokenCookie = new SetCookie({
    name: oidcContext.tokenCookieName,
    value: "-",
    maxAge: 0, //Expires immediately
    path: "/",
    secure: true,
    httpOnly: true
  });
  if (oidcContext.domain) {
    emptyTokenCookie.domain = oidcContext.domain;
  }
  return Promise.resolve(createResponse(
    200,
    {
      'content-type': ['text/plain'],
      'Set-Cookie': emptyTokenCookie.toHeader(),
    },
    "Logged out"
  ));
}


// MAIN entry point, configuration and routing
export async function responseProvider(request) {
  // Prepare context data
  const basedir = request.path.match(/.*\//)[0];
  const base = basedir.slice(1, -1).replaceAll('/', '_').toUpperCase();
  const variablePrefix = "PMUSER_" + (base ? `${base}_` : "");
  const oidcContext = {
    basedir,
    base,
    incomingHost: request.host,
    redirect: `https://${request.host}${basedir}callback`,
    //Cookies leveraged in auth flow
    nonceCookieName: `${base}-nonce`,
    stateCookieName: `${base}-state`,
    redirectUrlCookieName: `${base}-url`,

    // Property Manager variables
    akamaiSecret: request.getVariable(`${variablePrefix}AKSECRET`),
    clientId: request.getVariable(`${variablePrefix}CLIENTID`),
    clientSecret: request.getVariable(`${variablePrefix}SECRET`),
    auth: request.getVariable(`${variablePrefix}AUTH_URL`),
    domain: request.getVariable(`${variablePrefix}DOMAIN`),
    scope: request.getVariable(`${variablePrefix}SCOPE`) || "openid email",
    tokenCookieName: request.getVariable(`${variablePrefix}TOKEN_NAME`) || `__token__`,

  };
  // Special value auto is removing left-most dot part from incoming host
  if (oidcContext.domain === "auto") {
    oidcContext.domain = request.host.replace(/^[^.]+\./g, '');
  }

  // Request routing

  // initiate flow with IDP
  if (request.path.endsWith('/login')) {
    return oidcLogin(oidcContext, request);
  }

  // process callback request from IDP
  if (request.path.endsWith('/callback')) {
    return oidcCallback(oidcContext, request);
  }

  // logout clearing cookies
  if (request.path.endsWith('/logout')) {
    return oidcLogout(oidcContext, request);
  }

  // Unknown path
  return Promise.resolve(createResponse(404, { 'Content-Type': ['application/text'] }, `No route for ${request.url}`));
}
