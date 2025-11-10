---
layout: post
title: "Bypassing misconfigured Auth0 MFA implementations"
tags: [Auth0, MFA]
---

Some time ago, I was searching for bugs in a web application running Auth0. And because Auth0 is a popular OAuth provider (and implicitly very secure), I started looking deeper into its inner workings. The result was a bypass of a custom MFA implementation, which could have allowed an attacker full long-term access to any user's account.

Let's assume you found an XSS in an application running Auth0, or even better, an Account Takeover (ATO) vulnerability. You can now hijack the user's session and perform actions on their behalf. However, you do not have long-term access to that account, because you only have access to the session token, which is valid for a short period of time. In order to escalate the impact of the vulnerability, you would need to change the account's password or email.

The application I was testing, `target.com`, had such a vulnerability. However, in order to change the password, the current password was required, so this was not a viable option. The only option left was to change the email.

Upon clicking the "Change Email" button, the app would immediately log out the user and redirect them to the login page. Next time the user logged in, the app sent an email with an OTP code to the user's (original) email address. After completing the MFA flow, the app added a new scope, `email:update`, to the token, and the user would be able to change its email from the interface. So, the email change endpoint basically checked for the `email:update` scope and, if present, allowed the email change.

This is what Auth0 calls [Step-up authentication](https://auth0.com/docs/secure/multi-factor-authentication/step-up-authentication). As mentioned in the docs, "with step-up authentication, applications that allow access to different types of resources can require users to authenticate with a stronger authentication mechanism to access sensitive resources". In this case, the email change endpoint is the sensitive resource, requiring the `email:update` scope. Further in the docs, Auth0 mentions that "when your audience is an API, you can implement step-up authentication with Auth0 using scopes, access tokens, and Actions. When an application wants to access an API's protected resources, it must provide an access token. The resources that it will have access to depend on the permissions that are included in the access token. These permissions are defined as scopes".

Here is where the issue lies. The documentation mentions requiring a special scope for sensitive APIs. But, depending on the application, this may not be enough to ensure the security of the endpoint. Auth0 does not mention how this scope is added to the token. If you can somehow forge another authentication method, decoupled from the normal Auth0 login flow, you can mess with the scopes without triggering MFA.

On a normal login flow, implying the `password-realm` grant type, manually forging the `email:update` scope in the request triggers the MFA flow. In return, the token contains the `email:update` scope, as well as other infromation about the login mechanism, such as the connection used (in this case `"https://target.com/connection":"user-password"`).

![Auth0 Step-up authentication sequence](/assets/img/auth0_password_mfa_flow.svg){:width="90%"}

However, this is not the only possible login flow. Auth0 allows adding other connections - linking your account to other services, such as Google, Facebook, etc. Such a request can look like this:

<div class="request-response-flow">
  <div class="request-response-panel">
    <div class="request-response-panel__grid">
      <div class="request-response-panel__column request-response-panel__column--request">
        <span class="request-response-panel__badge">Request</span>
        <pre><code>POST /v1/user/link-accounts HTTP/2
Host: target.com
Content-Type: application/json
Authorization: Bearer access_token_given_by_auth0

{
    "primaryAccessToken":"primary_access_token_given_by_auth0",
    "secondaryAccessToken":"secondary_access_token_given_by_google"
}
</code></pre>
      </div>
      <div class="request-response-panel__column request-response-panel__column--response">
        <span class="request-response-panel__badge">Response</span>
        <pre><code>HTTP/2 200 OK
Content-Type: application/json

{
}
</code></pre>
      </div>
    </div>
  </div>
</div>

This further allows users to log in using their Google account. However, after the "Log in with Google" flow, the access token would contain a claim like `"https://target.com/connection":"google"`. Even if the login mechanism is different, that token can still be used everywhere in the application if endpoints are weakly enforced.

This was exactly the case for `target.com`. And because the email reset endpoint was protected only by the `email:update` scope, without checking how the token was obtained (if it was through `user-password` + MFA or through an external connection), forging a token with the Google login flow allowed me to perform full account takeover.

### The Attack

Let's take each step in detail.

1. First of all, get user's session token (partial account takeover) or gain some sort of XSS that allows advanced requests to the authentication endpoint.

2. Link your Google account to the user's account using the above request

3. Log back in with your Google account. When logging in with Google, the scopes would be granted by the Google auth flow, without triggering Auth0's MFA flow. This is what such a request would look like:

    <div class="request-response-flow">
    <div class="request-response-panel">
        <div class="request-response-panel__grid">
        <div class="request-response-panel__column request-response-panel__column--request">
            <span class="request-response-panel__badge">Request</span>
        <pre><code>GET /authorize?client_id=client1234567890&response_type=token&redirect_uri=https://target.com/callback&scope=openid%20profile%20email%20email:update&audience=https://api.target.com&connection=google&state=somerandomnonce&auth0Client=auth0client1234567890 HTTP/2
Host: auth.target.com
    </code></pre>
        </div>
        <div class="request-response-panel__column request-response-panel__column--response">
            <span class="request-response-panel__badge">Response</span>
            <pre><code>HTTP/2 302 Found
Location: https://accounts.google.com/o/oauth2/auth?response_type=code&redirect_uri=https://target.com/callback&scope=openid%20profile%20email%20email:update&state=somerandomnonce&client_id=client1234567890.apps.googleusercontent.com
    </code></pre>
        </div>
        </div>
    </div>
    </div>

4. Notice the request url containing the `email:update` scope. The flow finishes with an access token that contains the `email:update` scope, as well as the connection used (in this case `"https://api.target.com/connection":"google"`). Because the application does not check the connection, we can simply use this token to change the email.

![Auth0 Google login flow](/assets/img/auth0_google_flow.svg){:width="90%"}

### The Fix

The fix to such an issue is simple: either deny the authentication request using external connections if forged scopes exist, or implement an additional check in the sensitive endpoint to check the connection used to obtain the token. Even if Auth0 do not explicitly mention this in the documentation, a good reference is [this article](https://auth0.com/docs/secure/multi-factor-authentication/step-up-authentication/configure-step-up-authentication-for-web-apps) on how to configure step-up authentication for web apps. There, the endpoint checks if MFA was triggered by looking at the `amr` claim (authentication methods reference). Because the `amr` claim is present in the `id_token` (not in the `access_token` that APIs usually use), we can rely on other claims to determine how the user logged in, such as the `connection` or even `sub`.

I hope this article was useful and you learned something new. Oauth is a complex topic, so feel free to reach out to me for feedback or if you have any questions/further ideas.
