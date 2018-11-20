#include "tp.h"

#define X509_CONTENT_SPECIFIC_VERSION        0
#define X509_CONTENT_SPECIFIC_ISSUSERID      1
#define X509_CONTENT_SPECIFIC_SUBJECTID      2
#define X509_CONTENT_SPECIFIC_EXTENTION      3

#define Tp_X509_ASN1_TIME_UTC             0x17
#define Tp_X509_ASN1_TIME_GENERALIZED     0x18

#define Tp_x509_atoi2(_p, _val)    \
    do\
    {\
        (_val) = (_p[0]-'0')*10;\
        (_val) += (_p[1]-'0'); \
        _p+=2;\
    }while(0);\

#define Tp_x509_atoi4(_p, _val)  \
    do\
    {\
        (_val) = (_p[0]-'0')*1000;\
        (_val) += (_p[1]-'0')*100; \
        (_val) += (_p[2]-'0')*10; \
        (_val) += (_p[3]-'0'); \
        _p+=4;\
    }while(0);\



enum Tp_X509_RDN_OID
{
    Tp_X509_OID_MIN,

    Tp_X509_OID_COMMON_NAME = 1,              /*commonName*/
    Tp_X509_OID_SERIAL,                       /*serialNumber*/
    Tp_X509_OID_COUNTRY,                      /*countryName*/
    Tp_X509_OID_LOCAL_NAME,                   /*localityName*/
    Tp_X509_OID_PROVINCE,                     /*stateOrProvinceName*/
    Tp_X509_OID_ORGANZATION,                  /*organizationName*/
    Tp_X509_OID_UNIT_NAME,                    /*organizationalUnitName*/
    Tp_X509_OID_BUSINESS_CATEGORY,            /*businessCategory*/
    Tp_X509_OID_POSTAL_ADDRESS,               /*postalAddress*/
    Tp_X509_OID_POST_OFFICE_BOX,              /*postOfficeBox*/
    Tp_X509_OID_PKCS9_EMAIL,                  /*pkcs-9-at-emailAddress*/
    Tp_X509_OID_JURISDICTION_LOCAL,           /*jurisdictionOfIncorporationLocalityName*/
    Tp_X509_OID_JURISDICTION_PROVINCE,        /*jurisdictionOfIncorporationStateOrProvinceName*/
    Tp_X509_OID_JURISDICTION_COUNTRY,         /*jurisdictionOfIncorporationCountryName*/


    Tp_X509_OID_MAX
};

enum Tp_X509_FLAG
{
    Tp_X509_PUB_CACHE = 0
};

struct Tp_x509_time
{
    unsigned short year, mon, day;         /**< Date. */
    unsigned short hour, min, sec;         /**< Time. */
};

struct Tp_x509_rdn_item
{
    unsigned int nid;
    unsigned int oid_len;
    unsigned char oid_name[20];
};

struct Tp_x509_rdn_info
{
    char *info[Tp_X509_OID_MAX];
    int info_len[Tp_X509_OID_MAX];
};

typedef struct Tp_x509_cert_s
{
    struct Tp_x509_rdn_info *subject_detail;
    struct Tp_x509_rdn_info *issuer_detail;
    struct Tp_x509_time not_before;
    struct Tp_x509_time not_after;
    unsigned long flag;
    unsigned char *cache_group;
    unsigned char *cache_pub;
    unsigned int cache_pub_key_len;
    unsigned char *signedcertificate;
    unsigned char *serialnumber;
    unsigned char *signatue;
    unsigned char *issuer;
    unsigned char *subject;
    unsigned char *pub_key_alg;
    unsigned char *pub_key;
    unsigned char *algorithm_id;
    unsigned char *extention;
    unsigned char *sign;
    unsigned int pub_key_len;
	unsigned int sign_len;
    unsigned char version;
    unsigned int cert_type;
    unsigned int signedcertificate_len;
	unsigned int sigalg_len;

    int issuer_len;
    int subject_len;

    unsigned int raw_len;
    unsigned char *raw;
}Tp_x509_cert_t;

#define g_rdn_item_num  (sizeof(g_Tp_ssl_rdn_item)/sizeof(struct Tp_x509_rdn_item))

static inline int x509_parse_is_special_asn1(unsigned char *p)
{
    int bit8_7,bit5_1;

    bit8_7 = (*p)>>6;
    bit5_1 = (*p)&0x1f;

    if(bit8_7 != 2)
        return -220;

    return bit5_1;
}

static inline int x509_lenbyte2len_asn1(unsigned char **p, int len_bytes)
{
    int len = 0;

    if(len_bytes > 4)
        return -103;

    (*p)++;
    while(len_bytes--) {
        len |= (*(*p)++) << ((len_bytes)<<3);
    }

    return len;
}

static inline int x509_push_padding(unsigned char **p, unsigned char *end)
{
    int pass = 0;

    while(*p < end && **p == 0) {
        (*p)++;
        pass++;
    }

    return pass;
}

static inline int x509_get_len_asn1(unsigned char **p, int *pass_len)
{
    unsigned char bit_8;
    unsigned char bit_7_1;
    unsigned int len_bytes, len;

    bit_8 = (**p)&0x80;
    bit_7_1 = (**p)&0x7f;

    if(bit_8) {
        len_bytes = bit_7_1;
        len = x509_lenbyte2len_asn1(p, len_bytes);

    } else if(bit_8 == 0 && bit_7_1 != 0) {
        len = bit_7_1;
        (*p)++;
        len_bytes = 0;

    } else {
        len = -104;
        len_bytes = 0;
    }

    if(pass_len)
        *pass_len = len_bytes + 1;

    return len;
}

static inline int x509_parse_is_seque_asn1(unsigned char *p)
{
    /*Bit8-Bit7*/
    if(((*p)&0xc0) != 0)
        return -100;

    /*Bit 6*/
    if(((*p)&0x20) == 0)
        return -101;

    /*Bit5-Bit1*/
    if(((*p)&0x1F) != 16)
        return -102;

    return 0;
}


/*0x31*/
static inline int x509_parse_is_set_asn1(unsigned char *p)
{
    /*Bit8-Bit7*/
    if(((*p)&0xc0) != 0)
        return -100;

    /*Bit 6*/
    if(((*p)&0x20) == 0)
        return -101;

    /*Bit5-Bit1*/
    if(((*p)&0x1F) != 17)
        return -102;

    return 0;
}

/* *p == 0x04 */
static inline int  x509_parse_is_octet_asn1(unsigned char *p)
{
    if(((*p)&0xc0) != 0)
        return -230;

    if(((*p)&0x20) != 0)
        return -231;

    if(((*p)&0x1F) != 4)
        return -232;

    return 0;
}

/* *p == 0x03 */
static inline int  x509_parse_is_bitstring_asn1(unsigned char *p)
{
    if(((*p)&0xc0) != 0)
        return -230;

    if(((*p)&0x20) != 0)
        return -231;

    if(((*p)&0x1F) != 3)
        return -232;

    return 0;
}

/* *p == 0x02 */
static inline int  x509_parse_is_integer_asn1(unsigned char *p)
{
    if(((*p)&0xc0) != 0)
        return -230;

    if(((*p)&0x20) != 0)
        return -231;

    if(((*p)&0x1F) != 2)
        return -232;

    return 0;
}


/* *p == 0x06 */
static inline int x509_parse_is_obj_id_asn1(unsigned char *p)
{
    if(((*p)&0xc0) != 0)
        return -230;

    if(((*p)&0x20) != 0)
        return -231;

    if(((*p)&0x1F) != 6)
        return -232;

    return 0;
}

static inline void Tp_asn1_set_tag_val(unsigned char *out, unsigned short tag)
{
    *out = tag;
}

static inline void Tp_asn1_set_tag_len(unsigned char *out, unsigned int *len)
{
    unsigned int lenbyte;
    unsigned int in_len = *len;
    unsigned char *p = out;
    unsigned short rl = 24;
    unsigned char start = 0;

    if(in_len <= 127) {
        *p = in_len&0xFF;
        *len = 1;

    } else {
        p = out + 1;

        while(rl >= 0) {
            if(!start && !(in_len>>rl)) {
                rl -= 8;
                continue;
            }
            start = 1;
            *p++ = (in_len>>rl)&0xFF;
            rl -= 8;
        }

        lenbyte = (unsigned int)(p - out);
        *out = 0x80 | (lenbyte - 1);
        *len = lenbyte;
    }
}


static inline void Tp_asn1_set_seq_len(unsigned char *out, unsigned int *len)
{
    unsigned char *p = out;

    Tp_asn1_set_tag_val(p, 0x30);
    p++;

    Tp_asn1_set_tag_len(p, len);
    *len += 1;
}

static inline void Tp_asn1_set_integer_len(unsigned char *out, unsigned int *len)
{
    unsigned char *p = out;

    Tp_asn1_set_tag_val(p, 0x02);
    p++;

    Tp_asn1_set_tag_len(p, len);
    *len += 1;
}


struct Tp_x509_rdn_item g_Tp_ssl_rdn_item[] =
{
    {.nid = Tp_X509_OID_COMMON_NAME,             .oid_len = 3,  .oid_name = {0x55, 0x04, 0x03}},
    {.nid = Tp_X509_OID_SERIAL,                  .oid_len = 3,  .oid_name = {0x55, 0x04, 0x05}},
    {.nid = Tp_X509_OID_COUNTRY,                 .oid_len = 3,  .oid_name = {0x55, 0x04, 0x06}},
    {.nid = Tp_X509_OID_LOCAL_NAME,              .oid_len = 3,  .oid_name = {0x55, 0x04, 0x07}},
    {.nid = Tp_X509_OID_PROVINCE,                .oid_len = 3,  .oid_name = {0x55, 0x04, 0x08}},
    {.nid = Tp_X509_OID_ORGANZATION,             .oid_len = 3,  .oid_name = {0x55, 0x04, 0x0a}},
    {.nid = Tp_X509_OID_UNIT_NAME,               .oid_len = 3,  .oid_name = {0x55, 0x04, 0x0b}},

    {.nid = Tp_X509_OID_BUSINESS_CATEGORY,       .oid_len = 3,  .oid_name = {0x55, 0x04, 0x0f}},
    {.nid = Tp_X509_OID_POSTAL_ADDRESS,          .oid_len = 3,  .oid_name = {0x55, 0x04, 0x10}},
    {.nid = Tp_X509_OID_POST_OFFICE_BOX,         .oid_len = 3,  .oid_name = {0x55, 0x04, 0x12}},

    {.nid = Tp_X509_OID_PKCS9_EMAIL,             .oid_len = 9,  .oid_name = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01}},

    {.nid = Tp_X509_OID_JURISDICTION_LOCAL,      .oid_len = 11, .oid_name = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x01}},
    {.nid = Tp_X509_OID_JURISDICTION_PROVINCE,   .oid_len = 11, .oid_name = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x02}},
    {.nid = Tp_X509_OID_JURISDICTION_COUNTRY,    .oid_len = 11, .oid_name = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x03}},

};

void Tp_free_x509_cert(void *crt)
{
    Tp_x509_cert_t *x = crt;

    if(x->subject_detail)
        Tp_free(x->subject_detail);

    if(x->issuer_detail)
        Tp_free(x->issuer_detail);
}

int  x509_parse_rdn_simple(unsigned char **p, unsigned char **inner, int *inner_len)
{
    int ret;
    int issuer_len;

    ret = x509_parse_is_seque_asn1(*p);
    if(ret < 0)
        return ret;
    (*p)++;

    issuer_len = x509_get_len_asn1(p, NULL);
    if(issuer_len < 0)
        return issuer_len;

    (*inner) = *p;
    *inner_len = issuer_len;

    (*p) += issuer_len;
    return 0;
}

struct Tp_x509_rdn_item * Tp_x509_get_item_by_oid(unsigned char *oid, unsigned int oid_len)
{
    unsigned int i = 0;
    struct Tp_x509_rdn_item *item;

    for(i = 0; i < g_rdn_item_num; i++) {
        item = &g_Tp_ssl_rdn_item[i];

        if(item->oid_len != oid_len)
            continue;

        if(Tp_memcmp(item->oid_name, oid, oid_len))
            continue;

        return item;
    }

    return NULL;
}

void Tp_x509_parse_rdnseq(struct Tp_x509_rdn_info *info, unsigned char *rdn, int rdn_len)
{
    unsigned char *p = rdn, *q;
    int ret, len, len2, id_len, item_len, pass_len;
    struct Tp_x509_rdn_item *item;

    while(rdn_len > 0) {
        q = p;
        ret = x509_parse_is_set_asn1(p);
        if(unlikely(ret < 0))
            return ;

        p++;

        len = x509_get_len_asn1(&p, &pass_len);
        if(unlikely(len < 0))
            return ;

        rdn_len -= len + pass_len + 1;
        q = p;

        ret = x509_parse_is_seque_asn1(p);
        if(unlikely(ret < 0))
            return ;

        p++;

        len2 = x509_get_len_asn1(&p, NULL);
        if(unlikely(len2 < 0))
            return ;

        if(len2 + 2 != len)
            return ;

        /*06 03/0b */
        ret = x509_parse_is_obj_id_asn1(p);
        if(unlikely(ret < 0))
            return ;

        p++;

        id_len = x509_get_len_asn1(&p, NULL);
        if(unlikely(id_len < 0))
            return ;

        item = Tp_x509_get_item_by_oid(p, id_len);
        if(NULL == item) {
            p = q + len;
            continue;
        }

        p += id_len;

        p++;

        item_len = x509_get_len_asn1(&p, NULL);
        if(unlikely(id_len < 0))
            return ;

        info->info[item->nid] = (char*)p;
        info->info_len[item->nid] = (int)item_len;

        p += item_len;

        continue;
    }

}


void Tp_x509_new_rdn_detail( struct Tp_x509_rdn_info **p, unsigned char *rdn_raw, int rdn_len)
{
    struct Tp_x509_rdn_info *new_detail = NULL;

    new_detail = Tp_calloc(sizeof(struct Tp_x509_rdn_info));
    if(unlikely(NULL == new_detail))
        return;

    Tp_x509_parse_rdnseq(new_detail, rdn_raw, rdn_len);
    *p = new_detail;
}

int Tp_x509_get_time(struct Tp_x509_time *tm, unsigned char *asn1_start, int *pass_len)
{
    unsigned char *p = asn1_start;
    unsigned char time_type;
    int len = 0, pass = 0;
    int year = 0, mon = 0, day = 0, hour = 0, min = 0, sec = 0;

    time_type = *p++;

    if(likely(Tp_X509_ASN1_TIME_UTC == time_type)) {
        len = x509_get_len_asn1(&p, &pass);
        if(len < 0)
            return -1;

        Tp_x509_atoi2(p, year);

        /*RFC 2459
         *Where YY is greater than or equal to 50, the year shall be
         *interpreted as 19YY; and
         *Where YY is less than 50, the year shall be interpreted as 20YY.
         */
        if(year >= 50)
            year += 1900;
        else
            year += 2000;

        Tp_x509_atoi2(p, mon);
        Tp_x509_atoi2(p, day);
        Tp_x509_atoi2(p, hour);
        Tp_x509_atoi2(p, min);
        Tp_x509_atoi2(p, sec);

    } else if(Tp_X509_ASN1_TIME_GENERALIZED == time_type) {
        len = x509_get_len_asn1(&p, &pass);
        if(len < 0)
            return -2;

        Tp_x509_atoi4(p, year);
        Tp_x509_atoi2(p, mon);
        Tp_x509_atoi2(p, day);
        Tp_x509_atoi2(p, hour);
        Tp_x509_atoi2(p, min);
        Tp_x509_atoi2(p, sec);
    } else
        return -3;

    tm->year = year;
    tm->mon = mon;
    tm->day = day;
    tm->hour = hour;
    tm->min = min;
    tm->sec = sec;

    *pass_len = len + pass + 1;
    return 1;

}

static int _Tp_x509_parse_cert_asn1(Tp_x509_cert_t * cert)
{
    int ret = 0, len = 0, tm_len = 0, pass_len = 0;
    int signedcert_len, version_len, alg_len, cert_len;
    unsigned char *p = NULL, *end = NULL;
    unsigned char *sig_start       = NULL, *alg_start          = NULL;
    unsigned char *issuer_start    = NULL, *subject_start      = NULL;
    unsigned char *valid_start     = NULL, *pubkey_start       = NULL;
    unsigned char *extention_start = NULL;

    p = cert->raw;
    cert_len = cert->raw_len;
    end = p + cert_len;

    ret = x509_parse_is_seque_asn1(p);
    if(unlikely(ret < 0))
        return ret;

    p++;

    len = x509_get_len_asn1(&p, &pass_len);
    if(unlikely(len < 0))
        return len;

    if(unlikely(cert_len != len + pass_len + 1))
        return -105;

    cert->signedcertificate = sig_start = p;
    ret = x509_parse_is_seque_asn1(sig_start);
    if(unlikely(ret < 0))
        return ret;

    sig_start++;
    signedcert_len = x509_get_len_asn1(&sig_start, NULL);
    if(unlikely(signedcert_len < 0))
        return signedcert_len;

    alg_start =  sig_start + signedcert_len;
    if(unlikely(alg_start > end))
        return -106;

    cert->signedcertificate_len = (unsigned int)(alg_start - cert->signedcertificate);/*用来做签名*/

    ret = x509_parse_is_special_asn1(sig_start);
    if(unlikely(ret != X509_CONTENT_SPECIFIC_VERSION))
        goto serialnumber;

    sig_start++;

    version_len = *sig_start++;
    if(unlikely(version_len < 0))
        return version_len;

    if(unlikely(*sig_start++ != 2))
        return -107;

    len = x509_get_len_asn1(&sig_start, NULL);

    if(unlikely(len != 1))
        return -107;

    cert->version = *sig_start++;

serialnumber:

    if(unlikely(*sig_start != 2))
        goto signature;

    sig_start++;

    cert->serialnumber = sig_start;
    len = x509_get_len_asn1(&sig_start, NULL);
    sig_start += len;

signature:
    p = sig_start;
    ret = x509_parse_is_seque_asn1(p);
    if(unlikely(ret < 0))
        return ret;

    p++;
    alg_len = x509_get_len_asn1(&p, NULL);
    if(unlikely(alg_len < 0))
        return alg_len;

    cert->signatue = p;
    cert->sigalg_len = alg_len;

    issuer_start = p + alg_len;
    if(unlikely(issuer_start > alg_start))
        return -500;

    /*issuer*/
    p = issuer_start;
    ret = x509_parse_rdn_simple(&p, &cert->issuer, &cert->issuer_len);
    if(unlikely(ret < 0))
        return ret;

    valid_start = p;
    if(unlikely(valid_start > alg_start))
        return -501;

    p = valid_start;
    ret = x509_parse_is_seque_asn1(p);
    if(unlikely(ret < 0))
        return ret;

    p++;

    len = x509_get_len_asn1(&p, NULL);
    if(unlikely(len < 0))
        return len;

    subject_start = p + len;
    if(unlikely(subject_start > alg_start))
        return -502;

    Tp_x509_get_time(&cert->not_before, p, &tm_len);
    Tp_x509_get_time(&cert->not_after,  p + tm_len, &tm_len);

    p = subject_start;
    ret = x509_parse_rdn_simple(&p, &cert->subject, &cert->subject_len);
    if(unlikely(ret < 0))
        return ret;

    pubkey_start = p;
    if(unlikely(pubkey_start > alg_start))
        return -502;

    ret = x509_parse_is_seque_asn1(p);
    if(unlikely(ret < 0))
        return ret;

    p++;

    len = x509_get_len_asn1(&p, NULL);
    if(unlikely(len < 0))
        return len;

    extention_start = p + len;
    if(unlikely(extention_start > alg_start))
        return -502;

    ret = x509_parse_is_seque_asn1(p);
    if(unlikely(ret < 0))
        return ret;

    cert->pub_key_alg = p;

    p++;

    len = x509_get_len_asn1(&p, NULL);
    if(unlikely(len < 0))
        return len;

    p += len;

    if(*p == 0x05 && *(p+1) == 0x00)
        p += 2;

    ret = x509_parse_is_bitstring_asn1(p);
    if(unlikely(ret < 0))
        return ret;

    p++;

    len = x509_get_len_asn1(&p, NULL);
    if(unlikely(len < 0))
        return len;

    x509_push_padding(&p, alg_start);

    cert->pub_key = p;
    cert->pub_key_len = (unsigned int)(extention_start - p);

    p = extention_start;
    cert->extention = p;
    ret = x509_parse_is_special_asn1(p);
    if(unlikely(ret != X509_CONTENT_SPECIFIC_EXTENTION))
       goto algorithmindentifier;

    p++;

    len = x509_get_len_asn1(&p, NULL);
    if(unlikely(len < 0))
        return len;

    if(unlikely((p+len) != alg_start))
        return -109;

algorithmindentifier:
    p = alg_start;
    ret = x509_parse_is_seque_asn1(p);
    if(unlikely(ret < 0))
        return ret;

    p++;
    len = x509_get_len_asn1(&p, NULL);
    if(unlikely(len < 0))
        return len;

    cert->algorithm_id = p;

    p += len;

    ret = x509_parse_is_bitstring_asn1(p);
    if(unlikely(ret < 0))
        return ret;

    p++;

    len = x509_get_len_asn1(&p, NULL);
    if(unlikely(len < 0))
        return len;

    len -= x509_push_padding(&p, end);

    cert->sign = p;
    cert->sign_len = len;

    Tp_x509_new_rdn_detail(&cert->subject_detail, cert->subject, cert->subject_len);
    Tp_x509_new_rdn_detail(&cert->issuer_detail, cert->issuer, cert->issuer_len);
    return 1;
}

int Tp_x509_get_subject_rdn(Tp_x509_cert_t * cert)
{
    if(NULL == cert->subject_detail) {
        Tp_x509_new_rdn_detail(&cert->subject_detail, cert->subject, cert->subject_len);
        if(unlikely(NULL == cert->subject_detail))
            return 0;
    }

    return 1;
}

typedef struct {
    unsigned char oid[9];
    unsigned int oidlen;
    unsigned int ec;
    char *name;
    unsigned char namelen;
} Tp_oid_t;

Tp_oid_t Tp_oid[] =
{
    /*rsaEncryption*/
    {
        .oid = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01},
        .oidlen = 9,
        .ec = 0,
        .name = "rsaEncryption",
        .namelen = 13,
    },

    /*ecPublickey*/
    {
        .oid = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01},
        .oidlen = 7,
        .ec = 1,
        .name = "ecPublickey",
        .namelen = 11,
    },

    /*secg192r1*/
    {
        .oid = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01},
        .oidlen = 8,
        .name = "secp192r1",
        .namelen = 9,
    },

    /*secg224r1*/
    {
        .oid = {0x2B, 0x81, 0x04, 0x00, 0x21},
        .oidlen = 5,
        .name = "secp224r1",
        .namelen = 9,
    },

    /*secg239r1*/
    {
        .oid = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x04},
        .oidlen = 8,
        .name = "secp239r1",
        .namelen = 9,
    },

    /*secg256r1*/
    {
        .oid = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
        .oidlen = 8,
        .name = "secp256r1",
        .namelen = 9,
    },

    /*sm2*/
    {
        .oid = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D},
        .oidlen = 8,
        .name = "sm2",
        .namelen = 3,
    },

    /*secg283r1*/
    {
        .oid = {0x2B, 0x81, 0x04, 0x00, 0x11},
        .oidlen = 5,
        .name = "secp283r1",
        .namelen = 9,
    },

    /*secg384r1*/
    {
        .oid = {0x2B, 0x81, 0x04, 0x00, 0x22},
        .oidlen = 5,
        .name = "secp384r1",
        .namelen = 9,
    },

    /*secg521r1*/
    {
        .oid = {0x2B, 0x81, 0x04, 0x00, 0x23},
        .oidlen = 5,
        .name = "secp521r1",
        .namelen = 9,
    },

    {
        .name       = "sha512WithRSAEncryption",
        .namelen    = 23,
        .oid        = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d},
        .oidlen     = 9,
    },

    {
        .name       = "sha256WithRSAEncryption",
        .namelen    = 23,
        .oid        = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b},/*sha256WithRSAEncryption*/
        .oidlen     = 9,
    },

    {
        .name       = "sha1WithRSAEncryption",
        .namelen    = 21,
        .oid        = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05},/*sha1WithRSAEncryption*/
        .oidlen     = 9,
    },

    {
        .name       = "md5WithRSAEncryption",
        .namelen    = 20,
        .oid        = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04},/*md5WithRSAEncryption*/
        .oidlen     = 9,
    },

    {
        .name       = "md4WithRSAEncryption",
        .namelen    = 20,
        .oid        = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x03},/*md4WithRSAEncryption*/
        .oidlen     = 9,
    },

    {
        .name       = "md2WithRSAEncryption",
        .namelen    = 20,
        .oid        = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02},/*md2WithRSAEncryption*/
        .oidlen     = 9,
    },
    {
        .name       = "ecdsa_with_SHA1",
        .namelen    = 15,
        .oid        = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01},/*ecdsa_with_SHA1*/
        .oidlen     = 7,
    },

    {
        .name       = "ecdsa_with_SHA256",
        .namelen    = 17,
        .oid        = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02},/*ecdsa_with_SHA256*/
        .oidlen     = 8,
    },

    {
        .name       = "ecdsa_with_SHA512",
        .namelen    = 17,
        .oid        = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04},/*ecdsa_with_SHA512*/
        .oidlen     = 8,
    },

    {
        .name       = "sm2_with_sm3",
        .namelen    = 12,
        .oid        = {0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75},/*sm2_with_sm3*/
        .oidlen     = 8,

    },

    {
        .name       = "sha384WithRSAEncryption",
        .namelen    = 12,
        .oid        = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c},/*sha384WithRSAEncryption*/
        .oidlen     = 9,
    },
};

Tp_oid_t *Tp_get_oid_alg_oid(unsigned char *oid, unsigned int oid_len)
{
    int i = 0;

    for(i = 0; i < sizeof(Tp_oid)/sizeof(Tp_oid_t); i++)
    {
        if(Tp_oid[i].oidlen != oid_len)
        {
            continue;
        }

        if(!Tp_memcmp(oid, Tp_oid[i].oid, oid_len))
        {
            return &Tp_oid[i];
        }
    }

    return NULL;
}


Tp_oid_t * Tp_x509_get_oid(unsigned char **alg_id, unsigned alg_id_len)
{
    int ret, len;
    unsigned char *q = *alg_id;

    ret = x509_parse_is_obj_id_asn1(q);
    if(unlikely(ret < 0))
        return NULL;
    q++;

    len = x509_get_len_asn1(&q, NULL);
    if(unlikely(len < 0))
        return NULL;

    if (q + len > *alg_id + alg_id_len)
        return NULL;

    *alg_id = q + len;

    return Tp_get_oid_alg_oid(q, len);
}

int Tp_x509_parse_sigalg_oid(unsigned char *alg_id, unsigned int alg_len, char *type)
{
    Tp_oid_t *oid = NULL;
    unsigned char *q = alg_id;

    oid = Tp_x509_get_oid(&q, alg_len);

    Tp_memcpy(type, oid->name, oid->namelen);

    return 1;
}

int Tp_x509_parse_pkeyalg_oid(unsigned char *alg_id, char *type)
{
    Tp_oid_t *oid = NULL;
    int ret, alg_id_len, off;
    unsigned char *q = alg_id, *alg_id_end = NULL;

    ret = x509_parse_is_seque_asn1(q);
    if(unlikely(ret < 0))
        return 0;

    q++;

    alg_id_len = x509_get_len_asn1(&q, NULL);
    if(unlikely(alg_id_len < 0))
        return 0;

    alg_id_end = q + alg_id_len;

    oid = Tp_x509_get_oid(&q, alg_id_len);

    off = oid->namelen;
    Tp_memcpy(type, oid->name, off);

    if(unlikely(!oid->ec))
        return 1;

    if(unlikely(q >= alg_id_end))
        return 0;

    oid = Tp_x509_get_oid(&q, alg_id_len);

    type[off++]=',';
    Tp_memcpy(type + off, oid->name, oid->namelen);
    type[off + oid->namelen] = '\0';

    return 1;
}

int Tp_x509_parse_cert_asn1(Tp_ctx_t *ctx, Tp_x509_cert_t * cert)
{
    unsigned char *p, *end;
    int len;

    _Tp_x509_parse_cert_asn1(cert);

    end = cert->raw + cert->raw_len;

    if (ctx->cb.cert_serial_cb) {
        p = cert->serialnumber;
        len = x509_get_len_asn1(&p, NULL);
        if(unlikely(len < 0))
            return 0;

        if(p + len > end)
            return 0;

        ctx->cb.cert_serial_cb(ctx, (char*)p, (int)len);
    }

    if (ctx->cb.cert_sigalg_cb) {

        char _str[25];
        if (!Tp_x509_parse_sigalg_oid(cert->signatue, cert->sigalg_len ,_str))
            return 0;

        ctx->cb.cert_sigalg_cb(ctx, _str, (int)strlen(_str));
    }

    if (ctx->cb.cert_pkeyalg_cb) {

        char _str[25];
        if (!Tp_x509_parse_pkeyalg_oid(cert->pub_key_alg, _str))
            return 0;

        ctx->cb.cert_pkeyalg_cb(ctx, _str, (int)strlen(_str));
    }

    if (ctx->cb.cert_email_cb) {
        if (!Tp_x509_get_subject_rdn(cert))
            return 0;
        ctx->cb.cert_email_cb(ctx,
        cert->subject_detail->info[Tp_X509_OID_PKCS9_EMAIL],
        cert->subject_detail->info_len[Tp_X509_OID_PKCS9_EMAIL]);
    }


    if (ctx->cb.cert_cn_cb) {
        if (!Tp_x509_get_subject_rdn(cert))
            return 0;
        ctx->cb.cert_cn_cb(ctx,
        cert->subject_detail->info[Tp_X509_OID_COMMON_NAME],
        cert->subject_detail->info_len[Tp_X509_OID_COMMON_NAME]);
    }

    if (ctx->cb.cert_country_cb) {
        if (!Tp_x509_get_subject_rdn(cert))
            return 0;
        ctx->cb.cert_country_cb(ctx,
        cert->subject_detail->info[Tp_X509_OID_COUNTRY],
        cert->subject_detail->info_len[Tp_X509_OID_COUNTRY]);
    }

    if (ctx->cb.cert_local_cb) {
        if (!Tp_x509_get_subject_rdn(cert))
            return 0;
        ctx->cb.cert_local_cb(ctx,
        cert->subject_detail->info[Tp_X509_OID_LOCAL_NAME],
        cert->subject_detail->info_len[Tp_X509_OID_LOCAL_NAME]);
    }

    if (ctx->cb.cert_prov_cb) {
        if (!Tp_x509_get_subject_rdn(cert))
            return 0;
        ctx->cb.cert_prov_cb(ctx,
        cert->subject_detail->info[Tp_X509_OID_PROVINCE],
        cert->subject_detail->info_len[Tp_X509_OID_PROVINCE]);
    }

    if (ctx->cb.cert_org_cb) {
        if (!Tp_x509_get_subject_rdn(cert))
            return 0;
        ctx->cb.cert_org_cb(ctx,
        cert->subject_detail->info[Tp_X509_OID_ORGANZATION],
        cert->subject_detail->info_len[Tp_X509_OID_ORGANZATION]);
    }

    if (ctx->cb.cert_orgunit_cb) {
        if (!Tp_x509_get_subject_rdn(cert))
            return 0;
        ctx->cb.cert_orgunit_cb(ctx,
        cert->subject_detail->info[Tp_X509_OID_UNIT_NAME],
        cert->subject_detail->info_len[Tp_X509_OID_UNIT_NAME]);
    }

    if (ctx->cb.cert_email_cb) {
        if (!Tp_x509_get_subject_rdn(cert))
            return 0;
        ctx->cb.cert_email_cb(ctx,
        cert->subject_detail->info[Tp_X509_OID_PKCS9_EMAIL],
        cert->subject_detail->info_len[Tp_X509_OID_PKCS9_EMAIL]);
    }

    return 1;
}

int Tp_parse_cert(Tp_ctx_t *ctx, unsigned char *in, unsigned int len)
{
    Tp_x509_cert_t cert;
    int ret;

    Tp_memset(&cert, 0 ,sizeof(Tp_x509_cert_t));

    cert.raw = in;
    cert.raw_len = len;

    ret = Tp_x509_parse_cert_asn1(ctx, &cert);

    Tp_free_x509_cert(&cert);

    return ret;
}
