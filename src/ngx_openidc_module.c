/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone Holding BV - www.zmartzone.eu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

#include <stdlib.h>

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_config.h>

#include <oauth2/cfg.h>
#include <oauth2/mem.h>
#include <oauth2/nginx.h>
#include <oauth2/oauth2.h>
#include <oauth2/version.h>

typedef struct ngx_openidc_claim_t {
	char *name;
	char *value;
	struct ngx_openidc_claim_t *next;
} ngx_openidc_claim_t;

typedef struct ngx_openidc_cfg_t {
	ngx_conf_t *cf;
	ngx_openidc_claim_t *claims;
} ngx_openidc_cfg_t;

static void ngx_openidc_cleanup(void *data)
{
	// ngx_openidc_cfg_t *cfg = (ngx_openidc_cfg_t *)data;
}

static void *ngx_openidc_create_loc_conf(ngx_conf_t *cf)
{
	ngx_openidc_cfg_t *cfg = NULL;
	ngx_pool_cleanup_t *cln = NULL;

	cfg = ngx_pnalloc(cf->pool, sizeof(ngx_openidc_cfg_t));
	cfg->cf = cf;

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
	// ngx_openidc_cfg_t *prev = parent;
	ngx_openidc_cfg_t *cfg = child;

	cfg->cf = cf;

	return NGX_CONF_OK;
}
/*
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

static char *ngx_openidc_claim_command(ngx_conf_t *cf, ngx_command_t *cmd,
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

	claim = ngx_pnalloc(cf->pool, sizeof(ngx_openidc_claim_t));
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
*/
// clang-format off
static ngx_command_t ngx_openidc_commands[] = {
	ngx_null_command
};

static ngx_int_t ngx_openidc_post_config(ngx_conf_t *cf);

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
/*
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
*/

static ngx_int_t ngx_openidc_handler(ngx_http_request_t *r)
{
	ngx_int_t rv = NGX_DECLINED;
	// bool rc = false;
	oauth2_nginx_request_context_t *ctx = NULL;
	ngx_openidc_cfg_t *cfg = NULL;

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

	// ngx_set_target_variables(cfg, ctx, json_payload);

	rv = NGX_OK;

end:

	// hereafter we destroy the log object...
	oauth2_debug(ctx->log, "leave: %d", rv);

	if (ctx)
		oauth2_nginx_request_context_free(ctx);

	return rv;
}
