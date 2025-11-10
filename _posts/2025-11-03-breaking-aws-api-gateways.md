---
layout: post
title: "Breaking through AWS API Gateways - TFC CTF 2025"
tags: [AWS, API Gateway, Cognito, Cache Poisoning]
---

On 30 August 2025 we organized the fifth - and the largest - edition of
[TFC CTF](https://ctftime.org/event/2822). And because over the past year I've been messing a lot
with AWS, I decided to create a challenge combining some of the most interesting security issues
that can be found in AWS API Gateway, especially regarding Lambda Authorizers and Mapping Templates. 
In an attempt to make the challenge harder (and to frustrate ChatGPT), I chained the issues into an
exploit worthy of a cool article.

The challenge, "SilentClaim", was a web application that allowed users to login and take notes.
The application was built using AWS API Gateway, Cognito, DynamoDB and Lambda. The authorization
mechanism was implemented using a custom Lambda Authorizer and Mapping Templates. If you're not
familiar with these concepts, [AWS Docs](https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html) are a great primer.

The full challenge is available on my [GitHub](https://github.com/MateiBuzdea/TFCCTF-SilentClaim).

From the source code, we can see that the login is implemented using a Cognito user pool. This pool
has a custom Lambda trigger (feature of Amazon Cognito allowing further processing of the user data)
that allows the user to specify a custom claim named `role`, which will be added to the JWT
token and further used in the application. This claim is be default set to `writer` by the application
frontend. This is the first thing that we can notice about the application.

Then, looking at the API of the application, we can see that it has three main endpoints:
1. `/userinfo` - validates the JWT token against the Cognito user pool, returning the user's
information in the default OIDC standard. The token must be sent as an `Authorization` header and
it will be transformed by the ApiGW mapping template to a request for the default AWS Cognito API.
2. `/jwt` - returns the allowed request methods that the user can perform on the Notes endpoint, based
on the `role` claim in the JWT token. It can return `GET` or `POST`. It is created with a mock
ApiGW integration, with a custom mapping template that decodes and parses the JWT token.
3. `/notes/<id>` - takes an ID and communicates directly with a DynamoDB table, where notes are
stored. It is protected by a Lambda Authorizer that checks the user's JWT.

Before diving further into the application, let's take a small look at Mapping Templates. In API Gateway,
Mapping Templates are used to transform the request and response between the client and the API. They are
written in Velocity Template Language (VTL). The templates are applied to the request/response body
based on the value of the `Content-Type` header, so you can specify different templates for
different content types.

![Mapping Templates](/assets/img/api_gateway_diagram.svg)

However, if the content type does not match any of those defined by the
developer, the request/response body is handled differently. In this case, AWS has a special
parameter called `passthrough_behavior` that defines how the request/response body is handled. There
are three possible values:
* `WHEN_NO_MATCH` - if the content type does not match any of the defined templates, the
request/response body is passed through as is
* `WHEN_NO_TEMPLATES` - only if there are no templates, the request/response body is passed through
* `NEVER` - if the content type does not match any of the defined templates, the request/response
body is not processed
You can assume now the security implications of using the `WHEN_NO_MATCH` behavior.

Back to the application, let's tear each component apart.

We can see that the main endpoint, `/notes/<id>`, is protected by a Lambda Authorizer.
Looking at the source code, we can see that the Lambda Authorizer is implemented as follows:

```go
// Get user id
sub, err := fetchSub(ctx, apiBase, token)
fmt.Printf("DEBUG: /userinfo response - sub: %s, err: %v ", sub, err)
if err != nil || sub == "" {
    return unauthorized("cannot resolve sub"), nil
}

// Get allowed methods
allowed, err := fetchAllowedMethods(ctx, apiBase, token)
fmt.Printf("DEBUG: /jwt response - allowed methods: %v, err: %v ", allowed, err)
if err != nil || len(allowed) == 0 {
    return unauthorized("no allowed methods"), nil
}
```

It basically queries the `/userinfo` and `/jwt` endpoints to get the user id and the allowed
methods, respectively. So, in order to be able to pass these two checks, we need both the
`/userinfo` and `/jwt` endpoints to return valid responses.

Further in the authorizer, we can see that the output from the `/jwt` endpoint is directly used to
build the resources list, which is later used to build the allow policy.

```go
// Build resources list: same exact resource path, but for each allowed method
resources := make([]string, 0, len(allowed))
for _, m := range allowed {
    mu := strings.ToUpper(strings.TrimSpace(m))
    if mu == "" {
        continue
    }
    resource := fmt.Sprintf("%s/%s/%s/notes/%s/", baseArn, stage, mu, sub)
    resources = append(resources, resource)
}
```

Another thing to note is that the `/notes/` endpoint is using a proxy resource, meaning that any
path starting with `/notes/` will be processed by the DynamoDB integration. And because the
mapping template takes as ID the second path segment, we can inject any value we want after the
`/notes/` path as long as it contains a valid User ID at the beginning.

Looking at the `/jwt` endpoint, we can see a weird behavior: first of all it parses the JWT token
raw, without validating the signature. Second, it attempts to parse the `role` claim set by the
Lambda trigger, but if its value is not one of `reader` or `writer`, it will throw an error which
is not json formatted:

```velocity
#set($role = $claims.role)
...
#if($roleLower == "writer")
{ "methods": ["GET","POST"] }
#elseif($roleLower == "reader")
{ "methods": ["GET"] }
#else
$roleLower is not a valid role
#end
```

This error reflects the value of the `role` claim as is. And the `/jwt` endpoint response is used
by the Lambda Authorizer and parsed using `json.Unmarshal`, which ignores any trailing data:

```go
url := base + "/jwt"
req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
resp, err := httpClient.Do(req)
...

var j jwtResp
dec := json.NewDecoder(resp.Body)
if err := dec.Decode(&j); err != nil {
    return nil, err
}
```

So any valid JSON data set as the value of the `role` claim will be returned as an error by the
mapping template, but correctly parsed by the lambda authorizer. However, the post-login lambda
trigger does not allow non-alphanumeric characters in the `role` claim, so we need to find a
way to bypass this restriction.

Let's recap: we need to read the admin's note, so we need to be able to access the
`/notes/<admin-id>/anything/else/` endpoint. We are also limited by the Lambda Authorizer, which
needs to return a valid response from the `/userinfo` and `/jwt` endpoints. But if we can forge
a malformed JSON value as the `role` claim, we can bypass the restriction and inject any value we
want into the allow policy. How can we do that without making the `/userinfo` endpoint return an
error?

Here comes the last piece of the puzzle: Caching. The `/userinfo` endpoint has caching enabled and
the cache key is only created based on the path and the Authorization header. At first sight, this
could seem like a valid approach, but what if we forge a Bulk GET request?
Amazon API Gateway allows bulk GET requests for regional APIs (mainly because they are not routed
through CloudFront, so they are not caught by firewalls). The body of the request will not be
cached, so this can lead to cache poisoning.

Remember the previous discussion about mapping templates and their weird behavior? If we send a
request with an invalid content type header, an invalid JWT token in the Authorization header
(with a payload of our choice), but with a valid token in the body for the Cognito API to
parse, we will get a valid response, which will be cached under the wrong token.

<div class="request-response-flow">
  <div class="request-response-panel">
    <div class="request-response-panel__grid">
      <div class="request-response-panel__column request-response-panel__column--request">
        <span class="request-response-panel__badge">Request</span>
        <pre><code>GET /userinfo HTTP/2
Host: id.execute-api.eu-central-1.amazonaws.com
Authorization: Bearer FORGED.JWT.TOKEN
Content-Type: wrong/content-type

{"AccessToken":"VALID.COGNITO.TOKEN"}


</code></pre>
      </div>
      <div class="request-response-panel__column request-response-panel__column--response">
        <span class="request-response-panel__badge">Response</span>
        <pre><code>HTTP/2 200 OK
Content-Type: application/json

{
  "sub": "user-id",
  "email": "user@example.com",
}
</code></pre>
      </div>
    </div>
  </div>
</div>

This same cached response will then be returned to our lambda authorizer, which will pass the first
check.

Having all these pieces together, we can now craft the exploit:
1. Register and login. You now have a valid JWT token.
2. Modify the body of the current JWT token and add a valid JSON value as the "role" claim. This
value will be parsed by the lambda authorizer and will be used to build the allow policy. The value
should look like this: `{"methods":["GET/notes/<admin-id>"]}`.
3. Send a bulk GET request to the `/userinfo` endpoint with an invalid content type header, the
forged JWT in the Authorization header, and a request body of `{"AccessToken":"<correct_jwt>"}`.
The request will be ommitted by the mapping template and forwarded as is to the Cognito API, which
will correctly parse the request and cache the response under the wrong token.
4. Use the forget JWT to send a request to the `/notes/<admin-id>/notes/<your-id>/` endpoint. The
lambda authorizer will first query the `/userinfo` endpoint and the valid cached response will be
returned. It will continue by querying the `/jwt` endpoint, which will parse the forged role value,
will reflect it as-is and the authorizer will inject the payload directly inside the arn of the
Allow policy, allowing access to the admin's note.
5. Get the flag!
