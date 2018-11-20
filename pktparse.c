#include "tp.h"
#define TP_CHECK_END(n) \
    do {    \
        if (p + (n) > end) {\
            goto err;\
        }\
    }while(0);\

void TP_parse_ext(Tp_ctx_t *ctx, unsigned char *ext, unsigned int ext_len, unsigned char srv)
{
    unsigned short  len = 0;
    unsigned short  ext_type;
    unsigned short  sni_len;
    unsigned char   *p;

    while(ext_len > 0) {
        Tp_n2s(ext, ext_type);
        ext_len -= 2;
        Tp_n2s(ext, len);

        switch (ext_type)
        {
            case 0:
                if (!srv) {
                    p = ext;
                    p += 3;
                    Tp_n2s(p, sni_len);
                    //To do: parse list
                    if (ctx->cb.clnt_sni_cb) {
                        ctx->cb.clnt_sni_cb(ctx, (char*)p, (int)sni_len);
                    }
                }
            break;

            case 43:
                p = ext;
                if (len == 2) {
                    ctx->cb.srv_ver_cb(ctx, (char*)p, 2);
                }

            break;
            default:
            break;
        }
        ext += len;
        ext_len -= 2 + len;
    }

}

int Tp_clnt_hello(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    unsigned char *p = buf;
    unsigned char *end = buf + len;
    unsigned short cs, extlen;

    /*pass type, len*/
    p += 4;

    TP_CHECK_END(2);

    if (ctx->cb.clnt_ver_cb) {
        ctx->cb.clnt_ver_cb(ctx, (char*)p, 2);
    }

    p += 2;

    /*pass random*/
    p += 32;

    TP_CHECK_END(0);

    if (ctx->cb.clnt_id_cb) {
        ctx->cb.clnt_id_cb(ctx, (char*)(p + 1), (int)p[0]);
    }

    /*pass session id*/
    p += p[0] + 1;

    TP_CHECK_END(2);

    Tp_n2s(p, cs);

    if (ctx->cb.clnt_ciph_cb) {
        ctx->cb.clnt_ciph_cb(ctx, (char*)p, (int)cs);
    }

    /*pass cipher suit*/
    p += cs;

    /*pass compress*/
    p += p[0] + 1;

    /*no ext*/
    if (p + 2 >= end) {
        return len;
    }

    Tp_n2s(p, extlen);
    TP_parse_ext(ctx, p, extlen, 0);
    return len;
err:
    return -1;
}

int Tp_srv_hello(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    unsigned char *p = buf;
    unsigned char *end = buf + len;
    unsigned short extlen;

    /*pass type, len*/
    p += 4;

    TP_CHECK_END(2);

    /*will change if TLS 1.3 in ext*/
    if (ctx->cb.srv_ver_cb) {
        ctx->cb.srv_ver_cb(ctx, (char*)p, 2);
    }

    p += 2;

    /*pass random*/
    p += 32;

    TP_CHECK_END(0);

    if (ctx->cb.srv_id_cb) {
        ctx->cb.srv_id_cb(ctx, (char*)(p + 1), (int)p[0]);
    }

    /*pass session id*/
    p += p[0] + 1;

    TP_CHECK_END(2);

    if (ctx->cb.srv_ciph_cb) {
        ctx->cb.srv_ciph_cb(ctx, (char*)p, 2);
    }
    p += 2;

    TP_CHECK_END(0);

    /*pass compress*/
    p++;

    if (p + 2 > end)
        return len;

    Tp_n2s(p, extlen);
    TP_parse_ext(ctx, p, extlen, 1);

    /*ext*/
    return len;
err:
    return -1;
}

int Tp_srv_cert(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    unsigned char *p = buf;
    unsigned char *end;
    int cert_len, certs_len;

    p++;
    Tp_n2l3(p, len);
    end = p + len;
    len += 4;/*current frame len*/

    TP_CHECK_END(3);
    Tp_n2l3(p, certs_len);
    TP_CHECK_END(3);

    ctx->cert_level = 0;

    while (certs_len > 0) {
        Tp_n2l3(p, cert_len);
        certs_len -= 3;

        if (ctx->cb.cert_raw_cb) {
            ctx->cb.cert_raw_cb(ctx, (char*)p, (int)cert_len);
        }
        if (Tp_parse_cert(ctx, p, cert_len) < 0) {
            goto err;
        }
        p += cert_len;
        certs_len -= cert_len;
        ctx->cert_level++;
    }

    return len;
err:
    return -1;
}

int Tp_srv_ke(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    unsigned char *p = buf;
    unsigned char *end = p + len;

    p++;

    TP_CHECK_END(3);

    Tp_n2l3(p, len);
    end = p + len;

    len += 4;
#if 0
    TP_CHECK_END(3);

    p++;

    if (ctx->cb.srv_ke_curve_cb) {
        ctx->cb.srv_ke_curve_cb(ctx, (char*)p, 2);
    }

    p += 2;

    TP_CHECK_END(p[0] + 1);

    if (ctx->cb.srv_ke_pkey_cb) {
        ctx->cb.srv_ke_pkey_cb(ctx, (char*)(p + 1), (int)p[0]);
    }

    p += p[0] + 1;

    TP_CHECK_END(2);

    if (ctx->cb.srv_ke_sigalg_cb) {
        ctx->cb.srv_ke_sigalg_cb(ctx, (char*)p, 2);
    }

    p += 2;
#endif
    return len;

err:
    return -1;
}

int Tp_clnt_ke(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    unsigned char *p = buf;
    p++;
    Tp_n2l3(p, len);
    len += 4;

    return len;
}

int Tp_cert_vfy(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    unsigned char *p = buf;
    p++;
    Tp_n2l3(p, len);
    len += 4;

    return len;
}


int Tp_ccs(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    return len;
}

int Tp_app(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    return len;
}

int Tp_finish(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    return len;
}


int Tp_srv_cert_req(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    unsigned char *p = buf;

    ctx->clnt_vfy = 1;
    p++;
    Tp_n2l3(p, len);
    len += 4;

    return len;
}

int Tp_srv_done(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len)
{
    unsigned char *p = buf;
    p++;
    Tp_n2l3(p, len);
    len += 4;

    return len;
}

type_parser Tp_type_parser[23] =
{
    [1]  = Tp_clnt_hello,
    [2]  = Tp_srv_hello,
    [11] = Tp_srv_cert,
    [12] = Tp_srv_ke,
    [13] = Tp_srv_cert_req,
    [14] = Tp_srv_done,
    [15] = Tp_cert_vfy,
    [16] = Tp_clnt_ke,
};

