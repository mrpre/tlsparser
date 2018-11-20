#include "tp.h"

extern type_parser Tp_type_parser[23];

int Tp_is_reject(Tp_ctx_t *ctx)
{
    return ctx->flag&TP_FLAG_REJECT;
}

void Tp_set_reject(Tp_ctx_t *ctx)
{
    ctx->flag |= TP_FLAG_REJECT;
}

void *Tp_ctx_get_pri(Tp_ctx_t *ctx)
{
    return ctx->pri;
}

void Tp_ctx_set_pri(Tp_ctx_t *ctx, void *pri)
{
    ctx->pri = pri;
}

void *Tp_ctx_new(void)
{
    return Tp_calloc(sizeof(Tp_ctx_t));
}

void Tp_ctx_free(Tp_ctx_t *ctx)
{
    if (unlikely(ctx)) {
        return;
    }

    Tp_free(ctx);
}

int Tp_in_parsing(Tp_ctx_t *ctx)
{
    return (ctx->tls_state != Tp_ES);
}

int Tp_get_cert_level(Tp_ctx_t *ctx)
{
    return ctx->cert_level;
}
EXPORT_SYMBOL(Tp_get_cert_level);

/*0: server certificate
 *1: client certificate
 */
int Tp_get_cert_dir(Tp_ctx_t *ctx)
{
    return ctx->clnt_vfy;
}

void Tp_parse(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    unsigned char *parse_buf;
    int parse_len;

    if (ctx->err) {
        return;
    }

    while (len) {
        if (likely(ctx->state == Tp_READ_R_HEAD)) {

            unsigned char need = TLS_R_SIZE - ctx->record_save;

            ctx->body_save_len = 0;
            if (ctx->saved_body) {
                Tp_free(ctx->saved_body);
                ctx->saved_body = NULL;
                ctx->body_save_len = 0;
            }

            if (len < need) {
                Tp_memcpy(ctx->record, buf, len);
                ctx->record_save += len;
                return;

            } else {
                Tp_memcpy(ctx->record + ctx->record_save, buf, need);
                len -= need;
                buf += need;
                ctx->record_save = 0;
            }

            ctx->body_len = Tp_get_record_len(ctx->record);
            if (ctx->saved_body) {
                Tp_free(ctx->saved_body);
                ctx->saved_body = NULL;
                ctx->body_save_len = 0;
            }
        }

        ctx->state = Tp_READ_R_BODY;

        if (len + ctx->body_save_len < ctx->body_len) {

            if (!ctx->saved_body
                && NULL == (ctx->saved_body = Tp_malloc(ctx->body_len)))
            {
                ctx->err = 1;
                return;
            }

            Tp_memcpy(ctx->saved_body + ctx->body_save_len, buf, len);
            ctx->body_save_len += len;
            return;

        } else if (ctx->body_save_len) {
            unsigned int need = ctx->body_len- ctx->body_save_len;
            Tp_memcpy(ctx->saved_body + ctx->body_save_len, buf, need);
            parse_buf = ctx->saved_body;
            parse_len = ctx->body_len;
            len -= need;
            buf += need;
        } else {
            parse_buf = buf;
            parse_len = ctx->body_len;
            len -= ctx->body_len;
            buf += ctx->body_len;
        }

        /*May Multiple Handshake Messages*/
        while (parse_len > 0) {
            int type, ret;
            type = parse_buf[0];

            if (ctx->ccs
                || ctx->record[0]== 23) {
                parse_len = 0;

            } else  if (ctx->record[0] == 20) {
                parse_len -= 1;
                ctx->ccs = 1;

            } else if (type < 23 && Tp_type_parser[type]) {
                ret = Tp_type_parser[type](ctx, parse_buf, parse_len);
                if (ret < 0) {
                    ctx->err = 1;
                    return;
                }
                parse_len -= ret;

            } else {
                parse_len = 0;
            }
        }

        /*New record*/
        ctx->state = Tp_READ_R_HEAD;
    }
}

#ifdef __KERNEL__

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chenjiayuan");
static int __init tlspaser_init(void)
{
    printf("tlspaser init\n");
    return 0;
}

static void __exit tlspaser_exit(void)
{
    printf("tlspaser exit\n");
}

module_init(tlspaser_init);
module_exit(tlspaser_exit);
#endif

IMPL_CB(clnt_ver_cb);
IMPL_CB(clnt_ciph_cb);
IMPL_CB(clnt_id_cb);
IMPL_CB(clnt_sni_cb);
IMPL_CB(srv_ver_cb);
IMPL_CB(srv_id_cb);
IMPL_CB(srv_ciph_cb);
IMPL_CB(cert_raw_cb);
IMPL_CB(cert_sigalg_cb);
IMPL_CB(cert_pkeyalg_cb);
IMPL_CB(cert_sig_cb);
IMPL_CB(cert_pkey_cb);
IMPL_CB(cert_serial_cb);
IMPL_CB(cert_cn_cb);
IMPL_CB(cert_country_cb);
IMPL_CB(cert_local_cb);
IMPL_CB(cert_prov_cb);
IMPL_CB(cert_org_cb);
IMPL_CB(cert_orgunit_cb);
IMPL_CB(cert_email_cb);
IMPL_CB(srv_ke_curve_cb);
IMPL_CB(srv_ke_pkey_cb);
IMPL_CB(srv_ke_sigalg_cb);
EXPORT_SYMBOL(Tp_ctx_new);
EXPORT_SYMBOL(Tp_ctx_free);
EXPORT_SYMBOL(Tp_in_parsing);
EXPORT_SYMBOL(Tp_get_cert_dir);
EXPORT_SYMBOL(Tp_parse);
EXPORT_SYMBOL(Tp_ctx_get_pri);
EXPORT_SYMBOL(Tp_ctx_set_pri);
EXPORT_SYMBOL(Tp_is_reject);
EXPORT_SYMBOL(Tp_set_reject);

