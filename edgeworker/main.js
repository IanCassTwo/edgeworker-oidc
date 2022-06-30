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
import { EdgeAuth } from "auth/edgeauth.js";


// Utilities - randomstring
function randomString(len) {
  let s = '';
  while (s.length < len) s += (Math.random() * 36 | 0).toString(36);
  return s;
}

// Perform a request at the support system
async function jsonRequest(url) {
  var j = {};
  j.response = await httpRequest(url);
  j.text = await j.response.text();
  try {
    j.json = JSON.parse(j.text);
  } catch (e) {
    j.error = e.toString();
    j.errorDetail = `${j.error},text=${j.text}`;
  }
  return j;
}

// Create a cookie in one line
function newCookie(name, val, path) {
  var c = new SetCookie();
  c.name = name;
  c.value = val;
  c.path = path;
  c.secure = true;
  return c;
}

// Edgeworks don't support atob(), so we have to implement it ourselves
function decodeBase64url(s) {
  var e={},i,b=0,c,x,l=0,a,r='',w=String.fromCharCode,L=s.length;
  var A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for(i=0;i<64;i++){e[A.charAt(i)]=i;}
  for(x=0;x<L;x++){
      c=e[s.charAt(x)];b=(b<<6)+c;l+=6;
      while(l>=8){((a=(b>>>(l-=8))&0xff)||(x<(L-2)))&&(r+=w(a));}
  }
  return r;
};

// Unpack the jwt - note: we should verify the signature (not possible in edgeworkers and as we request the token directly we can skip that step)
function jwt2json(s) {
  var r = {};
  try {
    var a = s.split('.');
    r.header = JSON.parse(decodeBase64url(a[0]));
    r.payload = JSON.parse(decodeBase64url(a[1]));
    r.signature = a[2];
  } catch (e) {
    r.error = e.toString();
  }
  return r;
}

// Auth flow, step 1: Initiate the login by redirection to the login endpoint and storing the login mode
async function oidcLogin(oidcContext, request) {
  var params = new URLSearchParams(request.query);
  var responseHeaders = {};
  var cookList = [];

  // Setup redirect URL
  if (params.get('url')) 
    cookList.push(newCookie('oidcurl', params.get('url'), oidcContext.basedir).toHeader());
  
  // Generate and store a nonce
  var nonce = randomString(8);
  cookList.push(newCookie('nonce', nonce, oidcContext.basedir).toHeader());
  
  responseHeaders["set-cookie"] = cookList;
  responseHeaders.location = [ `${oidcContext.auth}?client_id=${oidcContext.clientId}&nonce=${nonce}&redirect_uri=${oidcContext.redirect}&response_type=code&scope=openid+email` ];
  return Promise.resolve(createResponse(302, responseHeaders, ''));
}

// Auth flow, step 2: Callback
// Request parameter: code - code to be used to fetch the token from the idp
// Cookie parameter: loginUrl - redirect url, debug_block (no retrieval), debug_info (collect response info)
async function oidcCallback (oidcContext, request) {
  var params = new URLSearchParams(request.query);
  var cookies = new Cookies(request.getHeader('Cookie'));
  var code = params.get("code");
  var redirecturl = cookies.get("oidcurl");
  var newCookies = [];
  var failureContent = {};
  var failureStatus = 400;

  if (!redirecturl)
    redirecturl = '/';

  if (code && redirecturl !== 'debug_block') {
    // Retrieve tokens for the code as passed in
    const tokenParams = `grant_type=authorization_code&redirect_uri=${oidcContext.redirect}&code=${code}`;
    const credentials = `client_id=${oidcContext.clientId}&client_secret=${oidcContext.clientSecret}`;
    var tokenResponse = await httpRequest(`${request.scheme}://${request.host}${oidcContext.basedir}/token`, {
          method: "POST",
          headers: { "Content-Type": ["application/x-www-form-urlencoded"]},
          body: `${tokenParams}&${credentials}`
      });

    if (tokenResponse.ok && redirecturl != 'debug_break') {
      var tokenResult = await tokenResponse.json(); 

      var jwtId = jwt2json(tokenResult.id_token);
      tokenResult.id_decode = jwtId;

      var nonce = cookies.get("nonce");
      if (!(jwtId && jwtId.payload && jwtId.payload.nonce && jwtId.payload.nonce === nonce))
        return Promise.resolve(createResponse(403,{}, 'Nonce failed'));

      // Set cookie: Access token
      // newCookies.push(newCookie('access_token', tokenResult.access_token, '/').toHeader());

        // Create the Akamai token
        var token_start_time = Math.trunc(Date.now() / 1000);
        var acl = ["/*"];
        var akamaitoken = "empty"
        var ea = new EdgeAuth({
          key: oidcContext.akamaiSecret,
          startTime: token_start_time,
          windowSeconds: tokenResult.expires_in,
          salt: jwtId.payload.hd,
          payload: jwtId.payload.email,
          escapeEarly: true,
        });
        akamaitoken = ea.generateACLToken(acl);

	var tok = newCookie('__token__', akamaitoken, '/');
	tok.maxAge = tokenResult.expires_in;
        newCookies.push(tok.toHeader());

        // Redirect if we can
        if (redirecturl !== "debug_info") {
          return Promise.resolve(createResponse(302, {
            'Set-Cookie': newCookies,
            'Location': [ redirecturl ]
          },
          ''));
        }

        var jwtAccess = jwt2json(tokenResult.access_token);
        tokenResult.access_decode = jwtAccess;

        //Details send back
        return Promise.resolve(createResponse(tokenResponse.status, {'Set-Cookie': newCookies}, JSON.stringify(tokenResult)));
    } else {
      // not tokenResponse.ok, use text instead of JSON as the response is not always JSON
      var x = await tokenResponse.text();
      try {
        failureContent = JSON.parse(x);
        failureContent.url = redirecturl;
      } catch (err) {
        failureContent.error = "callback_failure";
        failureStatus = tokenResponse.status;      
        failureContent.description = "callback received indicates error";
        failureContent.details = x;
        failureContent.path = `${request.scheme}://${request.host}${oidcContext.basedir}/token`
        failureContent.params = tokenParams;  
      }
    }
  } else { // no code given or debug_block requested
    failureContent.error = "precondition";
    failureContent.description = `callback request not initiated, redirect-url:${redirecturl}, query:${request.query}`;
  }

  // Response for failures
  return Promise.resolve(
    createResponse(failureStatus, {'content-type': ['application/json']}, JSON.stringify(failureContent)));  
}

// MAIN entry point, configuration and routing
export async function responseProvider (request) {
  var oidcContext = {};
  oidcContext.basedir = request.path.match(/.*\//)[0];
  oidcContext.base = oidcContext.basedir.slice(1,-1).replaceAll('/','_').toUpperCase();
  oidcContext.redirect = `https://${request.host}${oidcContext.basedir}callback`;

  // Property Manager variables
  oidcContext.akamaiSecret = request.getVariable(`PMUSER_${oidcContext.base}_AKSECRET`);
  oidcContext.clientId = request.getVariable(`PMUSER_${oidcContext.base}_CLIENTID`);
  oidcContext.clientSecret = request.getVariable(`PMUSER_${oidcContext.base}_SECRET`);
  oidcContext.auth = request.getVariable(`PMUSER_${oidcContext.base}_AUTH_URL`);
  
  if (request.path.endsWith('/login')) {
    return oidcLogin(oidcContext, request);
  }

  if (request.path.endsWith('/callback')) {
    return oidcCallback(oidcContext, request);
  } 
  
  //if (request.path.endsWith('/logout')) {
  //  return oidcLogout(request);
  //}  

  return Promise.resolve(createResponse(404, {'Content-Type': ['application/text']},`No route for ${request.url}`));
}
