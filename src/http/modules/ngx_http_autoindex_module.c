
/*
 * Copyright (C) Igor Sysoev
 * modified by Zed A. Shaw.
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if 0

typedef struct {
    ngx_buf_t     *buf;
    size_t         size;
    ngx_pool_t    *pool;
    size_t         alloc_size;
    ngx_chain_t  **last_out;
} ngx_http_autoindex_ctx_t;

#endif


typedef struct {
    ngx_str_t      name;
    size_t         utf_len;
    size_t         escape;
    size_t         escape_html;

    unsigned       dir:1;

    time_t         mtime;
    off_t          size;
} ngx_http_autoindex_entry_t;


typedef struct {
    ngx_flag_t     enable;
    ngx_flag_t     localtime;
    ngx_flag_t     exact_size;
} ngx_http_autoindex_loc_conf_t;


#define NGX_HTTP_AUTOINDEX_PREALLOCATE  50
#define MAX_NAME_LEN 512

static ngx_int_t ngx_http_autoindex_error(ngx_http_request_t *r,
    ngx_dir_t *dir, ngx_str_t *name);
static ngx_int_t ngx_http_autoindex_init(ngx_conf_t *cf);
static void *ngx_http_autoindex_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_autoindex_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_autoindex_commands[] = {

    { ngx_string("autoindex"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_autoindex_loc_conf_t, enable),
      NULL },

    { ngx_string("autoindex_localtime"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_autoindex_loc_conf_t, localtime),
      NULL },

    { ngx_string("autoindex_exact_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_autoindex_loc_conf_t, exact_size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_autoindex_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_autoindex_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_autoindex_create_loc_conf,    /* create location configuration */
    ngx_http_autoindex_merge_loc_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_autoindex_module = {
    NGX_MODULE_V1,
    &ngx_http_autoindex_module_ctx,        /* module context */
    ngx_http_autoindex_commands,           /* module directives */
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


static ngx_buf_t *
autoindex_generate_html(ngx_http_request_t *r, ngx_array_t entries,
    ngx_http_autoindex_loc_conf_t  *alcf)
{
    size_t                          len = 0;
    ngx_http_autoindex_entry_t     *entry;
    ngx_uint_t                      i;
    ngx_buf_t *b;

    entry = entries.elts;

    len = MAX_NAME_LEN * entries.nelts + 1024;

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) return NULL;

    *b->last++ = '[';
    *b->last++ = '"';
    b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);

    *b->last++ = '"';
    *b->last++ = ',';
    *b->last++ = '[';

    for (i = 0; i < entries.nelts; i++) {
        if(entry[i].name.len >= MAX_NAME_LEN) {
            // this name is too long, it's illegal
            continue;
        }

        *b->last++ = '"';
		/*
        if (entry[i].colon) {
             *b->last++ = '.';
             *b->last++ = '/';
        }
		*/
        if (entry[i].escape) {
             ngx_escape_uri(b->last, entry[i].name.data, entry[i].name.len,
                            NGX_ESCAPE_HTML);

             b->last += entry[i].name.len + entry[i].escape;

             // needs to be escaped
        } else {
             b->last = ngx_cpymem(b->last, entry[i].name.data,
                                  entry[i].name.len);
             // otherwise, it's done
        }

        if (entry[i].dir) {
            *b->last++ = '/';
        }

        *b->last++ = '"';

        if(i < entries.nelts-1) {
            *b->last++ = ',';
        }
    }

    *b->last++ = ']';
    *b->last++ = ']';

    return b;
}

static ngx_int_t
ngx_http_autoindex_handler(ngx_http_request_t *r)
{
    u_char                         *last, *filename;
    size_t                          len, allocated, root;
    ngx_err_t                       err;
    ngx_buf_t                      *b;
    ngx_int_t                       rc, size;
    ngx_str_t                       path;
    ngx_dir_t                       dir;
    ngx_uint_t                      level, utf8;
    ngx_pool_t                     *pool;
    ngx_time_t                     *tp;
    ngx_chain_t                     out;
    ngx_array_t                     entries;
    ngx_http_autoindex_entry_t     *entry;
    ngx_http_autoindex_loc_conf_t  *alcf;

    static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    if (r->uri.data[r->uri.len - 1] != '/') {
        return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_autoindex_module);

    if (!alcf->enable) {
        return NGX_DECLINED;
    }

    /* NGX_DIR_MASK_LEN is lesser than NGX_HTTP_AUTOINDEX_PREALLOCATE */

    last = ngx_http_map_uri_to_path(r, &path, &root,
                                    NGX_HTTP_AUTOINDEX_PREALLOCATE);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    allocated = path.len;
    path.len = last - path.data;
    if (path.len > 1) {
        path.len--;
    }
    path.data[path.len] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http autoindex: \"%s\"", path.data);

    if (ngx_open_dir(&path, &dir) == NGX_ERROR) {
        err = ngx_errno;

        if (err == NGX_ENOENT
            || err == NGX_ENOTDIR
            || err == NGX_ENAMETOOLONG)
        {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;

        } else if (err == NGX_EACCES) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;

        } else {
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(level, r->connection->log, err,
                      ngx_open_dir_n " \"%s\" failed", path.data);

        return rc;
    }

#if (NGX_SUPPRESS_WARN)

    /* MSVC thinks 'entries' may be used without having been initialized */
    ngx_memzero(&entries, sizeof(ngx_array_t));

#endif

    /* TODO: pool should be temporary pool */
    pool = r->pool;

    if (ngx_array_init(&entries, pool, 40, sizeof(ngx_http_autoindex_entry_t))
        != NGX_OK)
    {
        return ngx_http_autoindex_error(r, &dir, &path);
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type_len = sizeof("application/javascript") - 1;
	r->headers_out.content_type.len = sizeof("application/javascript") - 1;
	r->headers_out.content_type.data = (u_char *) "application/javascript";

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        if (ngx_close_dir(&dir) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_dir_n " \"%V\" failed", &path);
        }

        return rc;
    }

    filename = path.data;
    filename[path.len] = '/';

    if (r->headers_out.charset.len == 5
        && ngx_strncasecmp(r->headers_out.charset.data, (u_char *) "utf-8", 5)
           == 0)
    {
        utf8 = 1;

    } else {
        utf8 = 0;
    }

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            err = ngx_errno;

            if (err != NGX_ENOMOREFILES) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                              ngx_read_dir_n " \"%V\" failed", &path);
                return ngx_http_autoindex_error(r, &dir, &path);
            }

            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http autoindex file: \"%s\"", ngx_de_name(&dir));

        len = ngx_de_namelen(&dir);

        if (ngx_de_name(&dir)[0] == '.') {
            continue;
        }

        if (!dir.valid_info) {

            /* 1 byte for '/' and 1 byte for terminating '\0' */

            if (path.len + 1 + len + 1 > allocated) {
                allocated = path.len + 1 + len + 1
                                     + NGX_HTTP_AUTOINDEX_PREALLOCATE;

                filename = ngx_pnalloc(pool, allocated);
                if (filename == NULL) {
                    return ngx_http_autoindex_error(r, &dir, &path);
                }

                last = ngx_cpystrn(filename, path.data, path.len + 1);
                *last++ = '/';
            }

            ngx_cpystrn(last, ngx_de_name(&dir), len + 1);

            if (ngx_de_info(filename, &dir) == NGX_FILE_ERROR) {
                err = ngx_errno;

                if (err != NGX_ENOENT) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                                  ngx_de_info_n " \"%s\" failed", filename);

                    if (err == NGX_EACCES) {
                        continue;
                    }

                    return ngx_http_autoindex_error(r, &dir, &path);
                }

                if (ngx_de_link_info(filename, &dir) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                                  ngx_de_link_info_n " \"%s\" failed",
                                  filename);
                    return ngx_http_autoindex_error(r, &dir, &path);
                }
            }
        }

        entry = ngx_array_push(&entries);
        if (entry == NULL) {
            return ngx_http_autoindex_error(r, &dir, &path);
        }

        entry->name.len = len;

        entry->name.data = ngx_pnalloc(pool, len + 1);
        if (entry->name.data == NULL) {
            return ngx_http_autoindex_error(r, &dir, &path);
        }

        ngx_cpystrn(entry->name.data, ngx_de_name(&dir), len + 1);

        entry->escape = 2 * ngx_escape_uri(NULL, ngx_de_name(&dir), len,
                                           NGX_ESCAPE_URI_COMPONENT);

        entry->escape_html = ngx_escape_html(NULL, entry->name.data,
                                             entry->name.len);

        if (utf8) {
            entry->utf_len = ngx_utf8_length(entry->name.data, entry->name.len);
        } else {
            entry->utf_len = len;
        }

        entry->dir = ngx_de_is_dir(&dir);
        entry->mtime = ngx_de_mtime(&dir);
        entry->size = ngx_de_size(&dir);
    }

    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%s\" failed", &path);
    }

    b = autoindex_generate_html(r, entries, alcf);


    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}



static ngx_int_t
ngx_http_autoindex_error(ngx_http_request_t *r, ngx_dir_t *dir, ngx_str_t *name)
{
    if (ngx_close_dir(dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%V\" failed", name);
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static void *
ngx_http_autoindex_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_autoindex_loc_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_autoindex_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->localtime = NGX_CONF_UNSET;
    conf->exact_size = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_autoindex_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_autoindex_loc_conf_t *prev = parent;
    ngx_http_autoindex_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->localtime, prev->localtime, 0);
    ngx_conf_merge_value(conf->exact_size, prev->exact_size, 1);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_autoindex_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_autoindex_handler;

    return NGX_OK;
}
