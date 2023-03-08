[![Build Status](https://github.com/OpenIDC/ngx_openidc_module/actions/workflows/build.yml/badge.svg)](https://github.com/OpenIDC/ngx_openidc_module/actions/workflows/build.yml)

# ngx_openidc_module

A module for the NGINX web server that makes NGINX operate as an OpenID Connect Relying Party and setting
headers/environment variables based on the information provided in the ID Token and returned from the
User Info endpoint.

## Configuration 

TODO

`OpenIDCProvider`  
Configures the OpenID Connect Provider settings.

`OpenIDCClient`  
Configures the OpenID Connect Client settings.

`OpenIDCClaim`  
Populates configuration variables based on available claims.

`OpenIDCCryptoPassphrase`
Set the passphrase used for encryption of cache, cookies, state etc.

`OpenIDCCache`
Configures a (default or named) cache backend.

`OpenIDCSession`
Configures the session type and options, e.g. cache/cookie, session duration, etc.

```nginx
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
