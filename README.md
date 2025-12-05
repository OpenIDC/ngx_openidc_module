[![Build Status](https://github.com/OpenIDC/ngx_openidc_module/actions/workflows/build.yml/badge.svg)](https://github.com/OpenIDC/ngx_openidc_module/actions/workflows/build.yml)

# ngx_openidc_module

A module for the NGINX web server that makes NGINX operate as an OpenID Connect Relying Party and setting
headers/environment variables based on the information provided in the ID Token and returned from the
User Info endpoint.

## Configuration 

The following module directives are set under an NGINX `location` block.

### OpenIDCProvider

`OpenIDCProvider (file|string|url) <provider-config-json> [session=<session-cookie-name>];`

Configures the OpenID Connect Provider config. The `provider-config-json` can be provided as a local `file`, a `string` containing the JSON object, or a `url` to the JSON config. Identity providers supporting discovery will have this JSON config available under the path `/.well-known/openid-configuration`.

Example:

```
# 3 different ways to provide the config:
OpenIDCProvider file /etc/nginx/conf.d/provider.json;
OpenIDCProvider string '{"issuer":"https://keycloak.example.com", ...}';
OpenIDCProvider url https://accounts.google.com/.well-known/openid-configuration;
```

### OpenIDCClient

`OpenIDCClient (string|json|file) <client-config> [ssl_verify=on|off];`

Configures the OpenID Connect Client settings. The `client-config` can be provided as a `string` that is form-encoded (eg. `key1=value1&key2=value2`), a `json` string, or a local `file` containing a JSON object.  The keys that are required to be set in the config are:

 * `client_id` - the client identifier
 * `client_secret` - the client password for authentication 
 * `scope` - request that specific sets of information be made available as Claim Values. Multiple scope values are space-delimited. OpenID Connect requests MUST contain the `openid` scope value.
 * `token_endpoint_auth_method` - how the client should authenticate.  Supported values are: `none`, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `client_cert`, `basic`.

Example:
```
# 3 different ways to provide the client settings:
OpenIDCClient string client_id=myapp&client_secret=3GrV8... ssl_verify=off;
OpenIDCClient json '{"client_id": "myapp", "client_secret": "3GrV8...", ...}' ssl_verify=off;
OpenIDCClient file /etc/nginx/conf.d/client.json ssl_verify=off;
```

### OpenIDCClaim

`OpenIDCClaim <claim-name> $<variable-name>;`

Populates configuration variables based on available claims from the [ID token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken). Refer to your provider's documentation for the available fields/claims available. Each line of `OpenIDCClaim` maps one claim to one variable (i.e.  to map 3 variables, you will need 3 config lines).

Example:
```
# Mapping three different claims:
OpenIDCClaim iss $pfc_claim_iss;
OpenIDCClaim sub $pfc_claim_sub;
OpenIDCClaim aud $pfc_claim_aud;
```

### OpenIDCCryptoPassphrase

`OpenIDCCryptoPassphrase <passphrase>;`

Set the passphrase used for encryption of cache, cookies, state etc. Optional - if a passphrase isn't set, a random passphrase will be generated each time the NGINX server is started.

Example:
```
OpenIDCCryptoPassphrase fde1afb7063f;
```

### OpenIDCCache

`OpenIDCCache <shm|file|redis|memcache> [form-encoded-options];`

Configures a (default or named) cache backend. Optional - defaults to `shm`. Form-encoded options include:

* `key_hash_algo` - a supported OpenSSL digest algorithm.  Defaults to `sha256`.
* `passphrase_hash_algo` - a supported OpenSSL digest algorithm. Defaults to `sha256`.
* `encrypt` - whether to encrypt or not. Set to `true` to encrypt.

Example:
```
OpenIDCCache shm key_hash_algo=sha256&passphrase_hash_algo=sha256&encrypt=false;
```

### OpenIDCSession

`OpenIDCSession <cookie|cache> [form-encoded-options];`

Configures the session type and options, e.g. cache/cookie, session duration, etc. Optional, defaults to `cookie`.  Form-encoded options include:

 * `cookie.name` - defaults to `openidc_session`
 * `cookie.path` - defaults to `/`
 * `max_duration` - defaults to 28800 seconds (8 hours)
 * `inactivity_timeout` - defaults to 300 seconds (5 minutes)

Example:
```
OpenIDCSession cookie cookie.name=openidc_session&cookie.path=/&max_duration=28800&inactivity_timeout=300;
```

### OpenIDCConfig

`OpenIDCConfig <form-encoded-options>;`

Configures global setting such as redirect URI, etc. Options include:

* `handler_path` - defaults to `/openid-connect`
* `redirect_uri` - the uri to redirect to after authenticating on the identity provider. Defaults to `$handler_path` + `/redirect_uri`
* `state.cookie.name.prefix` - defaults to `openidc_state_`
* `state.cookie.timeout` - defaults to 300 seconds (5 minutes)
* `state.cookie.max` - defaults to 6
* `state.cookie.delete.oldest` - defaults to false
* `unauth_action` - Defines the action to be taken when an unauthenticated request is made. Defaults to `auth`.  Available values: 
    * `auth` - user is redirected to the OpenID Connect Provider or Discovery page.
    * `pass` - unauthenticated request will pass but claims will still be passed when a user happens to be authenticated already
    * `401` - HTTP 401 Unauthorized is returned
    * `410` - HTTP 410 Gone is returned

Example:
```
OpenIDCConfig handler_path=/openid-connect&redirect_uri=/redirect_uri;
```

## Samples

```nginx
      location /openid-connect {
            # reference to provider Discovery metadata
            OpenIDCProvider file /etc/nginx/conf.d/provider.json;
            OpenIDCClient string client_id=openidc0&client_secret=secret&scope=openid%20profile&token_endpoint_auth_method=client_secret_basic ssl_verify=false;

            OpenIDCClaim sub $pfc_claim_sub;

            proxy_set_header OAUTH2_CLAIM_sub $pfc_claim_sub;
            proxy_pass http://echo:8080/headers$is_args$args;
        }
```

## Support

#### Community Support
For generic questions, see the Wiki pages with Frequently Asked Questions at:  
  [https://github.com/OpenIDC/ngx_openidc_module/wiki](https://github.com/OpenIDC/ngx_openidc_module/wiki)  
Any questions/issues should go to issues tracker.

#### Commercial Services
For commercial Support contracts, Professional Services, Training and use-case specific support you can contact:  
  [sales@openidc.com](mailto:sales@openidc.com)  


Disclaimer
----------
*This software is open sourced by OpenIDC. For commercial support
you can contact [OpenIDC](https://www.openidc.com) as described above in the [Support](#support) section.*
