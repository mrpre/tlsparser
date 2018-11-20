#ifndef __TP_H__
#define __TP_H__

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/slab.h>
#define Tp_calloc(n)    kzalloc((n), GFP_ATOMIC)/*don't schedule*/
#define Tp_malloc(n)    kmalloc((n), GFP_ATOMIC)/*don't schedule*/
#define Tp_free(p)      kfree((p))
#define printf          printk
#else
#include <malloc.h>
#include <string.h>
#define Tp_calloc(n)    calloc(1, (n))
#define Tp_malloc(n)    malloc((n))
#define Tp_free(p)      free((p))
#define likely(x)       (x)
#define unlikely(x)     (x)
#define EXPORT_SYMBOL(x)
#endif
#define TP_FLAG_REJECT (1<<0)

struct Tp_ctx_s;
typedef struct Tp_ctx_s Tp_ctx_t;
typedef int (*type_parser)(Tp_ctx_t *, unsigned char *, unsigned int);
typedef int (*Tp_callback_f)(Tp_ctx_t *, char *, unsigned int);

#define Tp_memcpy(d, s, n)  memcpy((d), (s), (n))
#define Tp_memcmp(s1, s2, n)  memcmp((s1), (s2), (n))
#define Tp_memset(d, s, n)  memset((d), (s), (n))
#define TLS_R_SIZE  5

#define Tp_n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| \
			    (((unsigned int)(c[1]))    )),c+=2)
#define Tp_n2l3(c,l)	((l =(((unsigned long)(c[0]))<<16)| \
     (((unsigned long)(c[1]))<< 8)| \
     (((unsigned long)(c[2]))    )),c+=3)

typedef enum {

    Tp_READ_R_HEAD = 0,
    Tp_READ_R_BODY,

} Tp_state;

typedef enum {

    Tp_CH, Tp_SH, Tp_SC, Tp_SK, Tp_HD, Tp_SF, Tp_CK, Tp_CF, Tp_ES

} Tp_tls_state;


typedef struct {
    unsigned char *data;
    unsigned int  len;
} Tp_str;

typedef struct {
    unsigned int req_ver;/*request TLS version*/
    Tp_str *server_name;
} Tp_ch_t;

typedef struct {
    unsigned int neg_ver;/*negotiated TLS version*/
    unsigned int neg_ciph;/*negotiated cipher suit*/
    unsigned int neg_resume;/*reume or not*/
} Tp_sh_t;

typedef struct {
    Tp_str *seq;
    Tp_str *cn;
    Tp_str *sig;
    Tp_str *pubkey;

    Tp_str *sigalg;
    Tp_str *keyalg;
} Tp_sc_t;

typedef struct {
    Tp_str *curve;
    Tp_str *pubkey;
    unsigned int sigalg;
} Tp_sk_t;

typedef struct {
    Tp_str *pubkey;
} Tp_ck_t;

typedef struct Tp_callback_s {
    Tp_callback_f clnt_ver_cb;
    Tp_callback_f clnt_ciph_cb;
    Tp_callback_f clnt_id_cb;
    Tp_callback_f clnt_sni_cb;
    Tp_callback_f srv_ver_cb;
    Tp_callback_f srv_id_cb;
    Tp_callback_f srv_ciph_cb;
    Tp_callback_f srv_ke_curve_cb;
    Tp_callback_f srv_ke_pkey_cb;
    Tp_callback_f srv_ke_sigalg_cb;
    Tp_callback_f cert_raw_cb;
    Tp_callback_f cert_ver_cb;
    Tp_callback_f cert_sigalg_cb;
    Tp_callback_f cert_pkeyalg_cb;
    Tp_callback_f cert_sig_cb;
    Tp_callback_f cert_pkey_cb;
    Tp_callback_f cert_serial_cb;

    Tp_callback_f cert_cn_cb;
    Tp_callback_f cert_country_cb;
    Tp_callback_f cert_local_cb;
    Tp_callback_f cert_prov_cb;
    Tp_callback_f cert_org_cb;
    Tp_callback_f cert_orgunit_cb;
    Tp_callback_f cert_email_cb;
} Tp_callback_t;

struct Tp_ctx_s {
    unsigned char  err;
    Tp_state       state;
    Tp_tls_state   tls_state;
    unsigned char  record[TLS_R_SIZE];
    unsigned char  record_save;
    unsigned int   body_len;
    unsigned int   body_save_len;
    unsigned char* saved_body;
    unsigned char  cert_level;
    unsigned char  clnt_vfy;
    unsigned char  ccs;
    void *pri;
    unsigned long  flag;
    struct Tp_callback_s  cb;
};


static inline Tp_str *Tp_str_new(unsigned char *data, unsigned int len)
{
    Tp_str *s = Tp_malloc(sizeof(Tp_str) + len);

    if (likely(s)) {
        s->len  = len;
        s->data = (unsigned char*)s + sizeof(Tp_str);
        if (data) {
            Tp_memcpy(s->data, data, len);
        }
    }

    return s;
}

static inline void Tp_str_free(Tp_str *s)
{
    if (likely(s)) {
        Tp_free(s);
    }
}

static inline int Tp_get_record_len(unsigned char *r)
{
    unsigned int len = 0;
    r+=3;
    Tp_n2s(r, len);
    return len;
}

#define IMPL_CB(_name)  \
    void Tp_set_##_name(Tp_ctx_t *ctx, Tp_callback_f func)\
    {\
        if (func == NULL) {     \
            return;             \
        }                       \
                                \
        ctx->cb._name = func;\
    }\
    EXPORT_SYMBOL(Tp_set_##_name);

#define DECLARE_CB(_name)  \
    void Tp_set_##_name(Tp_ctx_t *ctx, Tp_callback_f func);

DECLARE_CB(clnt_ver_cb);
DECLARE_CB(clnt_ciph_cb);
DECLARE_CB(clnt_id_cb);
DECLARE_CB(clnt_sni_cb);
DECLARE_CB(srv_ver_cb);
DECLARE_CB(srv_id_cb);
DECLARE_CB(srv_ciph_cb);
DECLARE_CB(cert_raw_cb);
DECLARE_CB(cert_sigalg_cb);
DECLARE_CB(cert_pkeyalg_cb);
DECLARE_CB(cert_sig_cb);
DECLARE_CB(cert_pkey_cb);
DECLARE_CB(cert_serial_cb);
DECLARE_CB(cert_cn_cb);
DECLARE_CB(cert_country_cb);
DECLARE_CB(cert_local_cb);
DECLARE_CB(cert_prov_cb);
DECLARE_CB(cert_org_cb);
DECLARE_CB(cert_orgunit_cb);
DECLARE_CB(cert_email_cb);
DECLARE_CB(srv_ke_curve_cb);
DECLARE_CB(srv_ke_pkey_cb);
DECLARE_CB(srv_ke_sigalg_cb);

int Tp_parse_cert(Tp_ctx_t *ctx, unsigned char *in, unsigned int len);
int Tp_get_cert_dir(Tp_ctx_t *ctx);
int Tp_get_cert_level(Tp_ctx_t *ctx);
void *Tp_ctx_new(void);
void Tp_parse(Tp_ctx_t *ctx, unsigned char *buf, unsigned int len);
void Tp_ctx_free(Tp_ctx_t *ctx);

#endif
