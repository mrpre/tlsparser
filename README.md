# tlsparser

## Introduction
A tinny TLS parser written by C without any dependency.   
It can be compiled both in userspace and kernel space.
It can be used to parse TLS packet and get some useful information.

 
## Usage

### Kernel space
For kernelspace usage, using `make` to build tlsparser.ko. (see `https://github.com/mrpre/ipvstls` for more about kernel usage)  
### User space  

#### Daemon
`gcc daemon.c parser.c pktparse.c  certparse.c -g -Wall -o tlsparser`  
`./tlsparser`   


#### Common usage
  
`
    /*create ctx*/
    Tp_ctx_t *ctx = Tp_ctx_new();

    /*once server name in ClientHello parsed, get_clnt_sni will be called*/
    Tp_set_clnt_sni_cb(ctx, get_clnt_sni);

    /*once common name in Certificate(both client and server) is parsed, get_cert_cn will by called*/
    Tp_set_cert_cn_cb(ctx, get_cert_cn);

    /*setting another callback here, more in interface.txt*/
    ......

    /*input the TLS segment*/
    Tp_parse(ctx, $TLSDATA1, $TLSDATA1_LEN);
    Tp_parse(ctx, $TLSDATA2, $TLSDATA1_LEN2);
    ......
    Tp_ctx_free(ctx);
`  

See `daemon.c` for more usage.  

## Interface  
More instructions about interface are in the `interface.txt`  

