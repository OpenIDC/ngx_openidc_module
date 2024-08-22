/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_config.h>

#include <oauth2/cfg.h>
#include <oauth2/mem.h>
#include <oauth2/nginx.h>
#include <oauth2/oauth2.h>
#include <oauth2/openidc.h>
#include <oauth2/session.h>
#include <oauth2/version.h>

typedef struct ngx_openidc_claim_t {
	char *name;
	char *value;
	struct ngx_openidc_claim_t *next;
} ngx_openidc_claim_t;

typedef struct ngx_openidc_cfg_t {
	ngx_conf_t *cf;
	oauth2_cfg_openidc_t *openidc;
	ngx_openidc_claim_t *claims;
	// TODO:
	oauth2_log_t *log;
} ngx_openidc_cfg_t;

static void ngx_openidc_cleanup(void *data)
{
	ngx_openidc_cfg_t *cfg = (ngx_openidc_cfg_t *)data;
	if (cfg->openidc)
		oauth2_cfg_openidc_free(NULL, cfg->openidc);
}

static void *ngx_openidc_create_loc_conf(ngx_conf_t *cf)
{
	ngx_openidc_cfg_t *cfg = NULL;
	ngx_pool_cleanup_t *cln = NULL;

	cfg = ngx_pcalloc(cf->pool, sizeof(ngx_openidc_cfg_t));
	cfg->log = NULL;
	cfg->cf = cf;

	cfg->openidc = oauth2_cfg_openidc_init(NULL);
	;
	cfg->claims = NULL;

	// TODO: correct level
	// oauth2_log_t *log = oauth2_log_init(OAUTH2_LOG_TRACE1, NULL);

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (cln == NULL)
		goto end;

	cln->handler = ngx_openidc_cleanup;
	cln->data = cfg;

end:

	return cfg;
}

static char *ngx_openidc_merge_loc_conf(ngx_conf_t *cf, void *parent,
					void *child)
{
	ngx_openidc_cfg_t *prev = parent;
	ngx_openidc_cfg_t *cfg = child;

	cfg->cf = cf;

	// TODO:...
	oauth2_cfg_openidc_merge(NULL, cfg->openidc, prev->openidc,
				 cfg->openidc);

	return NGX_CONF_OK;
}

static ngx_int_t ngx_openidc_claim_variable(ngx_http_request_t *r,
					    ngx_http_variable_value_t *v,
					    uintptr_t data)
{
	ngx_openidc_claim_t *claim = (ngx_openidc_claim_t *)data;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		       "ngx_openidc_claim_variable: %s=%s",
		       claim && claim->name ? claim->name : "(null)",
		       claim && claim->value ? claim->value : "(null)");

	if (claim && claim->value) {
		v->len = strlen(claim->value);
		v->data = ngx_palloc(r->pool, v->len);
		ngx_memcpy(v->data, claim->value, v->len);
	}

	if (v->len) {
		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;
	} else {
		v->not_found = 1;
	}

	return NGX_OK;
}

static char *ngx_openidc_set_claim(ngx_conf_t *cf, ngx_command_t *cmd,
				   void *conf)
{
	char *rv = NGX_CONF_ERROR;
	// ngx_http_core_loc_conf_t *clcf = NULL;
	ngx_openidc_cfg_t *cfg = (ngx_openidc_cfg_t *)conf;
	// ngx_http_compile_complex_value_t ccv;
	ngx_str_t *value = NULL;
	ngx_http_variable_t *v;
	ngx_openidc_claim_t *claim = NULL, *ptr = NULL;

	value = cf->args->elts;

	claim = ngx_pcalloc(cf->pool, sizeof(ngx_openidc_claim_t));
	claim->name = oauth2_strndup((const char *)value[1].data, value[1].len);
	claim->value = NULL;

	if (value[2].data[0] != '$') {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				   "invalid variable name \"%V\"", &value[2]);
		goto end;
	}

	value[2].len--;
	value[2].data++;

	v = ngx_http_add_variable(cf, &value[2], 0);
	if (v == NULL) {
		rv = "ngx_http_add_variable failed";
		goto end;
	}

	v->get_handler = ngx_openidc_claim_variable;
	v->data = (uintptr_t)claim;

	claim->next = NULL;
	if (cfg->claims == NULL) {
		cfg->claims = claim;
	} else {
		for (ptr = cfg->claims; ptr->next; ptr = ptr->next)
			;
		ptr->next = claim;
	}

	rv = NGX_CONF_OK;

end:

	return rv;
}

OAUTH2_NGINX_CFG_FUNC_ARGS1(openidc, ngx_openidc_cfg_t, passphrase,
			    oauth2_crypto_passphrase_set, NULL)
OAUTH2_NGINX_CFG_FUNC_ARGS2(openidc, ngx_openidc_cfg_t, cache,
			    oauth2_cfg_set_cache, NULL)
OAUTH2_NGINX_CFG_FUNC_ARGS3(openidc, ngx_openidc_cfg_t, provider,
			    oauth2_cfg_openidc_provider_resolver_set_options,
			    cfg->openidc)
OAUTH2_NGINX_CFG_FUNC_ARGS3(openidc, ngx_openidc_cfg_t, client,
			    oauth2_openidc_client_set_options, cfg->openidc)
OAUTH2_NGINX_CFG_FUNC_ARGS1(openidc, ngx_openidc_cfg_t, config,
			    oauth2_cfg_openidc_set_options, cfg->openidc)
OAUTH2_NGINX_CFG_FUNC_ARGS2(openidc, ngx_openidc_cfg_t, session,
			    oauth2_cfg_session_set_options, NULL)

static ngx_command_t ngx_openidc_commands[] = {
    OAUTH2_NGINX_CMD(1, openidc, "OpenIDCCryptoPassphrase", passphrase),
    OAUTH2_NGINX_CMD(12, openidc, "OpenIDCCache", cache),
    OAUTH2_NGINX_CMD(23, openidc, "OpenIDCClient", client),
    OAUTH2_NGINX_CMD(12, openidc, "OpenIDCSession", session),
    OAUTH2_NGINX_CMD(23, openidc, "OpenIDCProvider", provider),
    OAUTH2_NGINX_CMD(1, openidc, "OpenIDCConfig", config),
    OAUTH2_NGINX_CMD(2, openidc, "OpenIDCClaim", claim),
    ngx_null_command};

static ngx_int_t ngx_openidc_post_config(ngx_conf_t *cf);

// clang-format off

static ngx_http_module_t ngx_openidc_module_ctx = {
		NULL,						/* preconfiguration              */
		ngx_openidc_post_config,	/* postconfiguration             */

		NULL,						/* create main configuration     */
		NULL,						/* init main configuration       */

		NULL,						/* create server configuration   */
		NULL,						/* merge server configuration    */

		ngx_openidc_create_loc_conf,	/* create location configuration */
		ngx_openidc_merge_loc_conf	/* merge location configuration  */
};

ngx_module_t ngx_openidc_module = {
		NGX_MODULE_V1,
		&ngx_openidc_module_ctx,	/* module context    */
		ngx_openidc_commands,	/* module directives */
		NGX_HTTP_MODULE,		/* module type       */
		NULL,					/* init master       */
		NULL,					/* init module       */
		NULL,					/* init process      */
		NULL,					/* init thread       */
		NULL,					/* exit thread       */
		NULL,					/* exit process      */
		NULL,					/* exit master       */
		NGX_MODULE_V1_PADDING
};
// clang-format on

static ngx_int_t ngx_openidc_handler(ngx_http_request_t *r);

static ngx_int_t ngx_openidc_post_config(ngx_conf_t *cf)
{
	ngx_int_t rv = NGX_ERROR;
	ngx_http_handler_pt *h = NULL;
	ngx_http_core_main_conf_t *cmcf = NULL;
	ngx_openidc_cfg_t *cfg = NULL;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL)
		goto end;

	*h = ngx_openidc_handler;

	cfg = (ngx_openidc_cfg_t *)ngx_http_conf_get_module_loc_conf(
	    cf, ngx_openidc_module);

	if (cfg == NULL)
		goto end;

	rv = NGX_OK;

end:

	return rv;
}

static void ngx_set_target_variable(ngx_openidc_cfg_t *cfg,
				    oauth2_nginx_request_context_t *ctx,
				    const char *key, const char *val)
{
	ngx_openidc_claim_t *ptr = NULL;
	ptr = cfg->claims;
	while (ptr) {
		if (strcmp(ptr->name, key) == 0)
			break;
		ptr = ptr->next;
	}
	if (ptr) {
		ptr->value = oauth2_strdup(val);
	}
}

// TODO: generalize/callback part of this (at least the looping and encoding is
// generic)
static void ngx_set_target_variables(ngx_openidc_cfg_t *cfg,
				     oauth2_nginx_request_context_t *ctx,
				     json_t *json_token)
{
	void *iter = NULL;
	const char *key = NULL;
	json_t *value = NULL;
	char *val = NULL;
	iter = json_object_iter(json_token);
	while (iter) {
		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);
		if (json_is_string(value)) {
			val = oauth2_strdup(json_string_value(value));
		} else {
			val = oauth2_json_encode(ctx->log, value,
						 JSON_ENCODE_ANY);
		}

		ngx_set_target_variable(cfg, ctx, key, val);

		if (val)
			oauth2_mem_free(val);
		iter = json_object_iter_next(json_token, iter);
	}
}

static ngx_int_t ngx_openidc_handler(ngx_http_request_t *r)
{
	ngx_int_t rv = NGX_DECLINED;
	bool rc = false;
	oauth2_nginx_request_context_t *ctx = NULL;
	ngx_openidc_cfg_t *cfg = NULL;
	oauth2_http_response_t *response = NULL;
	json_t *claims = NULL;

	if (r != r->main)
		goto end;

	cfg = (ngx_openidc_cfg_t *)ngx_http_get_module_loc_conf(
	    r, ngx_openidc_module);
	if (cfg == NULL) {
		oauth2_warn(ctx->log,
			    "ngx_http_get_module_loc_conf returned NULL");
		rv = NGX_ERROR;
		goto end;
	}
	ctx = oauth2_nginx_request_context_init(r);
	if (ctx == NULL) {
		oauth2_warn(ctx->log,
			    "openidc_nginx_request_context_init returned NULL");
		rv = NGX_ERROR;
		goto end;
	}

	/*
	char *v = NULL;
	if (r->uri.len > 0) {
		v = oauth2_strndup((const char *)r->uri.data, r->uri.len);
		oauth2_http_request_path_set(ctx->log, ctx->request, v);
		oauth2_mem_free(v);
	};

	if (r->args.len > 0) {
		v = oauth2_strndup((const char *)r->args.data, r->args.len);
		oauth2_http_request_query_set(ctx->log, ctx->request, v);
		oauth2_mem_free(v);
	}
	*/
	oauth2_debug(ctx->log, "enter");

	// TODO: we can move this up to avoid overhead (and have no logs...)
	if ((cfg->openidc == NULL) || oauth2_cfg_openidc_provider_resolver_get(
					  ctx->log, cfg->openidc) == NULL)
		goto end;

	rc = oauth2_openidc_handle(ctx->log, cfg->openidc, ctx->request,
				   &response, &claims);

	if (rc == false) {
		oauth2_warn(ctx->log, "oauth2_openidc_handle failed");
		rv = NGX_ERROR;
		goto end;
	}

	ngx_set_target_variables(cfg, ctx, claims);

	rv = oauth2_nginx_http_response_set(ctx->log, response, r);

end:

	if (claims)
		json_decref(claims);

	if (ctx) {
		if (response)
			oauth2_http_response_free(ctx->log, response);
		// hereafter we destroy the log object...
		oauth2_debug(ctx->log, "leave: %d", rv);
		oauth2_nginx_request_context_free(ctx);
	}

	return rv;
}
