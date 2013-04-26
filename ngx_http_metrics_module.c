/*
 * vim: ft=c
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <yajl/yajl_gen.h>

#define yajl_gen_cstring(g, str) yajl_gen_string(g, (const unsigned char *)str, strlen(str))
#define YAJL_CHECK(meth) do { \
    if (meth != yajl_gen_status_ok) { \
        return NGX_ERROR; \
    } \
} while (0)

#define NGX_HTTP_LAST_LEVEL_500  508
#define NGX_HTTP_NUM_STATUS_CODES (NGX_HTTP_LAST_LEVEL_500 - NGX_HTTP_OK)

ngx_atomic_t *ngx_http_metrics_status_codes;

static
ngx_int_t ngx_http_metrics_gen_stub_status(yajl_gen g)
{
    YAJL_CHECK(yajl_gen_cstring(g, "requests"));
    YAJL_CHECK(yajl_gen_integer(g, *ngx_stat_requests));

    YAJL_CHECK(yajl_gen_cstring(g, "accepted"));
    YAJL_CHECK(yajl_gen_integer(g, *ngx_stat_accepted));

    YAJL_CHECK(yajl_gen_cstring(g, "handled"));
    YAJL_CHECK(yajl_gen_integer(g, *ngx_stat_handled));

    YAJL_CHECK(yajl_gen_cstring(g, "connections"));
    YAJL_CHECK(yajl_gen_integer(g, *ngx_stat_active));

    YAJL_CHECK(yajl_gen_cstring(g, "reading"));
    YAJL_CHECK(yajl_gen_integer(g, *ngx_stat_reading));

    YAJL_CHECK(yajl_gen_cstring(g, "writing"));
    YAJL_CHECK(yajl_gen_integer(g, *ngx_stat_writing));

    return NGX_OK;
}

static
ngx_int_t ngx_http_metrics_gen_status_counters(yajl_gen g)
{
    YAJL_CHECK(yajl_gen_cstring(g, "status_codes"));

    YAJL_CHECK(yajl_gen_map_open(g));

    ngx_int_t i = 0;
    char buf[4];

    for (i = 0; i < NGX_HTTP_NUM_STATUS_CODES; i++) {
      if (ngx_http_metrics_status_codes[i] > 0) {
        snprintf(buf, 4, "%ld", NGX_HTTP_OK + i);
        YAJL_CHECK(yajl_gen_cstring(g, buf));
        YAJL_CHECK(yajl_gen_integer(g, ngx_http_metrics_status_codes[i]));
      }
    }

    YAJL_CHECK(yajl_gen_map_close(g));

    return NGX_OK;
}

static
ngx_int_t ngx_http_metrics_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_set(&r->headers_out.content_type, "text/plain");

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    yajl_gen g = yajl_gen_alloc(NULL);

    YAJL_CHECK(yajl_gen_map_open(g));

    if (ngx_http_metrics_gen_stub_status(g) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_metrics_gen_status_counters(g) != NGX_OK) {
        return NGX_ERROR;
    }

    YAJL_CHECK(yajl_gen_map_close(g));

    const unsigned char *json;
    size_t len;
    yajl_gen_get_buf(g, &json, &len);

    ngx_buf_t *b;
    b = ngx_create_temp_buf(r->pool, len + 1);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    b->last = ngx_copy(b->last, json, len);
    b->last = ngx_copy(b->last, "\n", 1);

    yajl_gen_clear(g);
    yajl_gen_free(g);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static
char *ngx_http_show_metrics(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_metrics_handler;

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_status_code_count_handler(ngx_http_request_t *r)
{
  if (r->headers_out.status >= NGX_HTTP_OK && r->headers_out.status < NGX_HTTP_LAST_LEVEL_500) {
    ngx_atomic_fetch_add(&ngx_http_metrics_status_codes[r->headers_out.status - NGX_HTTP_OK], 1);
  }

  return NGX_OK;
}

static ngx_int_t
ngx_http_metrics_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    ngx_http_handler_pt *h;
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_status_code_count_handler;

    ngx_shm_t shm;
    shm.size = NGX_HTTP_NUM_STATUS_CODES * sizeof(ngx_atomic_t);
    shm.name.len = sizeof("ngx_http_metrics");
    shm.name.data = (u_char *) "ngx_http_metrics";
    shm.log = cf->log;

    if (ngx_shm_alloc(&shm) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_metrics_status_codes = (ngx_atomic_t *)shm.addr;

    ngx_int_t i;
    for (i = 0; i < NGX_HTTP_NUM_STATUS_CODES; i++) {
      ngx_http_metrics_status_codes[i] = 0;
    }

    return NGX_OK;
}

/* module boilerplate */
static ngx_command_t ngx_http_metrics_commands[] = {

    { ngx_string("show_metrics"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_show_metrics,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_metrics_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_metrics_init,                 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_metrics_module = {
    NGX_MODULE_V1,
    &ngx_http_metrics_module_ctx,          /* module context */
    ngx_http_metrics_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
