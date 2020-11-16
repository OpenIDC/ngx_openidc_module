# ngx_openidc_module
An module for the NGINX web server which makes NGINX operate as an
OpenID Connect Relying Party and setting headers/environment
variables based on the information provided in the ID Token and returned from the User Info endpoint.

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
  [https://github.com/zmartzone/ngx_openidc_module/wiki](https://github.com/zmartzone/ngx_openidc_module/wiki)  
Any questions/issues should go to issues tracker.

#### Commercial Services
For commercial Support contracts, Professional Services, Training and use-case specific support you can contact:  
  [sales@zmartzone.eu](mailto:sales@zmartzone.eu)  


Disclaimer
----------
*This software is open sourced by ZmartZone IAM. For commercial support
you can contact [ZmartZone IAM](https://www.zmartzone.eu) as described above in the [Support](#support) section.*
