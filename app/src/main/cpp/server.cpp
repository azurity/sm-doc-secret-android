#include <jni.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

struct ServerCTX {
    int socket;
    SSL_CTX *ctx;
    BN_CTX *bn_ctx;
    BIGNUM *big;
    EVP_PKEY *pkey;
    X509 *pcert;
    X509_NAME *subj;
};

struct Session {
    int socket;
    sockaddr_in addr;
    SSL *ssl;
};

jstring errstr = nullptr;

int createSocket(short port, int lisnum) {
    if (lisnum < 1) {
        return 0;
    }
    int sockfd;
    sockaddr_in my_addr;
    in_addr_t ip = INADDR_ANY;
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        return 0;
    }
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = ip;
    if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1) {
        close(sockfd);
        return 0;
    }
    if (listen(sockfd, lisnum) == -1) {
        close(sockfd);
        return 0;
    }
    return sockfd;
}

bool createCTX(JNIEnv *env, ServerCTX *sctx) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    sctx->ctx = SSL_CTX_new(TLSv1_server_method());
    if (sctx->ctx == nullptr) {
        errstr = env->NewStringUTF("create ctx error");
        return false;
    }
    //
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();
    sctx->pkey = EVP_PKEY_new();
    RSA *rsa = RSA_new();
    sctx->bn_ctx = BN_CTX_new();
    BN_CTX_start(sctx->bn_ctx);
    sctx->big = BN_new();
    BN_one(sctx->big);
    BN_mul_word(sctx->big, 0x100);
    BN_mul_word(sctx->big, 0x100);
    BN_add_word(sctx->big, 1);
    if (!RSA_generate_key_ex(rsa, 1024, sctx->big, nullptr)) {
        errstr = env->NewStringUTF("rsa gen failed");
        return false;
    }
    EVP_PKEY_assign_RSA(sctx->pkey, rsa);
    sctx->subj = X509_NAME_new();
    X509_NAME_add_entry_by_NID(sctx->subj, 14, MBSTRING_ASC, (unsigned char *) "CN", -1, -1, 0);
    sctx->pcert = X509_new();
    X509_set_version(sctx->pcert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(sctx->pcert), 1);
    X509_gmtime_adj(X509_get_notBefore(sctx->pcert), 0);
    int days = 3650;
    X509_gmtime_adj(X509_get_notAfter(sctx->pcert), 60 * 60 * 24 * days);
    X509_set_subject_name(sctx->pcert, sctx->subj);
    X509_set_pubkey(sctx->pcert, sctx->pkey);
    X509_sign(sctx->pcert, sctx->pkey, EVP_md5());
    if (SSL_CTX_use_certificate(sctx->ctx, sctx->pcert) <= 0) {
        errstr = env->NewStringUTF(ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }
    if (SSL_CTX_use_PrivateKey(sctx->ctx, sctx->pkey) <= 0) {
        errstr = env->NewStringUTF(ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }
    //
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    //
    if (!SSL_CTX_check_private_key(sctx->ctx)) {
        errstr = env->NewStringUTF(ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }
    return true;
}

void releaseServerCTX(ServerCTX *ctx) {
    if (ctx->socket)close(ctx->socket);
    if (ctx->pcert)X509_free(ctx->pcert);
    if (ctx->pkey)EVP_PKEY_free(ctx->pkey);
    if (ctx->subj)X509_NAME_free(ctx->subj);
    if (ctx->big)BN_free(ctx->big);
    if (ctx->bn_ctx) {
        BN_CTX_end(ctx->bn_ctx);
        BN_CTX_free(ctx->bn_ctx);
    }
    if (ctx->ctx)SSL_CTX_free(ctx->ctx);
}

extern "C" JNIEXPORT jlong JNICALL
Java_net_imwork_a166q0w6939_ssltestndk_Server_createServer(JNIEnv *env, jobject self, jshort port) {
    int sock = createSocket(port, 5);
    if (sock == 0) {
        return 0;
    }
    ServerCTX *ctx = new ServerCTX();
    memset(ctx, 0, sizeof(ServerCTX));
    ctx->socket = sock;
    if (!createCTX(env, ctx)) {
        releaseServerCTX(ctx);
        return 0;
    }
    return (jlong) ctx;
}

extern "C" JNIEXPORT void JNICALL
Java_net_imwork_a166q0w6939_ssltestndk_Server_releaseServer(JNIEnv *env, jobject self, jlong ctx) {
    ServerCTX *pctx = (ServerCTX *) ctx;
    releaseServerCTX(pctx);
    delete pctx;
    return;
}

extern "C" JNIEXPORT jlong JNICALL
Java_net_imwork_a166q0w6939_ssltestndk_Server_acceptC(JNIEnv *env, jobject self, jlong ctx) {
    ServerCTX *pctx = (ServerCTX *) ctx;
    socklen_t len;
    sockaddr_in sock_addr;
    int socket;
    if ((socket = accept(pctx->socket, (struct sockaddr *) &sock_addr, &len)) == -1) {
        return 0;
    }
    ioctl(socket, FIONBIO, 1);
    SSL *ssl = SSL_new(pctx->ctx);
    SSL_set_fd(ssl, socket);
    SSL_set_accept_state(ssl);
    while (true) {
        int ret = SSL_do_handshake(ssl);
        if (ret == 1) {
            break;
        }
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            continue;
        } else {
            SSL_free(ssl);
            close(socket);
            return 0;
        }
    }
    Session *s = new Session();
    s->socket = socket;
    s->addr = sock_addr;
    s->ssl = ssl;
    return (jlong) s;
}

extern "C" JNIEXPORT jbooleanArray JNICALL
Java_net_imwork_a166q0w6939_ssltestndk_Server_select(JNIEnv *env, jobject self, jlongArray ss) {
    jsize len = env->GetArrayLength(ss);
    jlong *ssa = new jlong[len];
    env->GetLongArrayRegion(ss, 0, len, ssa);
    jbooleanArray jmask = env->NewBooleanArray(len);
    fd_set set;
    FD_ZERO(&set);
    int maxfd = 0;
    for (int i = 0; i < len; i++) {
        Session *ps = (Session *) ssa[i];
        FD_SET(ps->socket, &set);
        if (ps->socket > maxfd) {
            maxfd = ps->socket;
        }
    }
    timeval t;
    t.tv_sec = 1;
    t.tv_usec = 0;
    int ret = select(maxfd + 1, &set, nullptr, nullptr, &t);
    jboolean *mask = new jboolean[len];
    memset(mask, 0, len * sizeof(jboolean));
    if (ret > 0) {
        for (int i = 0; i < len; i++) {
            Session *ps = (Session *) ssa[i];
            if (FD_ISSET(ps->socket, &set)) {
                mask[i] = JNI_TRUE;
            }
        }
    } else if (ret == 0) {
        errstr = env->NewStringUTF("timeout");
    } else {
        errstr = env->NewStringUTF("select error");
    }
    env->SetBooleanArrayRegion(jmask, 0, len, mask);
    delete mask;
    return jmask;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_net_imwork_a166q0w6939_ssltestndk_Server_recv(JNIEnv *env, jobject self, jlong s) {
    Session *ps = (Session *) s;
    jbyte buf[256];
    memset(buf, 0, 256);
    SSL_read(ps->ssl, buf, 256);
    jbyteArray ret = env->NewByteArray(256);
    env->SetByteArrayRegion(ret, 0, 256, buf);
    return ret;
}

extern "C" JNIEXPORT void JNICALL
Java_net_imwork_a166q0w6939_ssltestndk_Server_send(JNIEnv *env, jobject self, jlong s,
                                                   jbyteArray jbuf) {
    Session *ps = (Session *) s;
    jbyte buf[256];
    env->GetByteArrayRegion(jbuf, 0, 256, buf);
    SSL_write(ps->ssl, buf, 256);
    return;
}

extern "C" JNIEXPORT void JNICALL
Java_net_imwork_a166q0w6939_ssltestndk_Server_close(JNIEnv *env, jobject self, jlong s) {
    Session *ps = (Session *) s;
    SSL_shutdown(ps->ssl);
    SSL_free(ps->ssl);
    close(ps->socket);
    delete ps;
    return;
}

extern "C" JNIEXPORT jstring JNICALL
Java_net_imwork_a166q0w6939_ssltestndk_Server_getErr(JNIEnv *env, jobject self) {
    return errstr;
}