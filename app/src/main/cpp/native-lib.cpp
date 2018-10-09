#include <jni.h>
#include <string>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

extern "C" JNIEXPORT jstring JNICALL
Java_net_imwork_a166q0w6939_ssltestndk_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    //SSL_library_init();
    //OpenSSL_add_all_algorithms();
    //SSL_load_error_strings();
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_net_imwork_a166q0w6939_ssltestndk_MainActivity_createSocket(JNIEnv *env, jobject self) {
    int sockfd;
    sockaddr_in my_addr;
    int port = 9000;
    int lisnum = 5;
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

extern "C" JNIEXPORT jstring JNICALL
Java_net_imwork_a166q0w6939_ssltestndk_MainActivity_accept(
        JNIEnv *env,
        jobject self,
        jint socket) {
    SSL_CTX *ctx;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLSv1_server_method());
    if (ctx == NULL) {
        return env->NewStringUTF("create ctx error");
    }
    //
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();
    EVP_PKEY *pkey = EVP_PKEY_new();
    RSA *rsa = RSA_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);
    BIGNUM *big = BN_new();
    BN_one(big);
    BN_mul_word(big, 0x100);
    BN_mul_word(big, 0x100);
    BN_add_word(big, 1);
    if (!RSA_generate_key_ex(rsa, 1024, big, nullptr)) {
        return env->NewStringUTF("rsa gen failed");
    }
    EVP_PKEY_assign_RSA(pkey, rsa);
    X509_NAME *subj = X509_NAME_new();
    X509_NAME_add_entry_by_NID(subj, 14, MBSTRING_ASC, (unsigned char *) "CN", -1, -1, 0);
    X509 *pcert = X509_new();
    X509_set_version(pcert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(pcert), 1);
    X509_gmtime_adj(X509_get_notBefore(pcert), 0);
    int days = 3650;
    X509_gmtime_adj(X509_get_notAfter(pcert), 60 * 60 * 24 * days);
    X509_set_subject_name(pcert, subj);
    X509_set_pubkey(pcert, pkey);
    X509_sign(pcert, pkey, EVP_md5());
    //
    //if (SSL_CTX_use_certificate_file(ctx, "/storage/emulated/0/SSLTestNDK/cacert.pem",
    //                                 SSL_FILETYPE_PEM) <= 0) {
    if (SSL_CTX_use_certificate(ctx, pcert) <= 0) {
        close(socket);
        char buf[256];
        sprintf(buf, "ca error %s", ERR_error_string(ERR_get_error(), nullptr));
        return env->NewStringUTF(buf);
    }
    //if (SSL_CTX_use_PrivateKey_file(ctx, "/storage/emulated/0/SSLTestNDK/privkey.pem",
    //                                SSL_FILETYPE_PEM) <= 0) {
    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        close(socket);
        char buf[256];
        sprintf(buf, "key error %s", ERR_error_string(ERR_get_error(), nullptr));
        return env->NewStringUTF(buf);
    }
    //
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    //
    if (!SSL_CTX_check_private_key(ctx)) {
        close(socket);
        char buf[256];
        sprintf(buf, "check error %s", ERR_error_string(ERR_get_error(), nullptr));
        return env->NewStringUTF(buf);
    }
    //
    socklen_t len;
    sockaddr_in their_addr;
    int newfd;
    if ((newfd = accept(socket, (struct sockaddr *) &their_addr, &len)) == -1) {
        close(socket);
        char buf[256];
        sprintf(buf, "accept error %u", errno);
        return env->NewStringUTF(buf);
    }
    SSL *ssl;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, newfd);
    if (SSL_accept(ssl) == -1) {
        close(newfd);
        close(socket);
        char buf[256];
        sprintf(buf, "ssl handshake error %s", ERR_error_string(ERR_get_error(), nullptr));
        return env->NewStringUTF(buf);
    }
    char buf[1024];
    SSL_read(ssl, buf, 1024);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(newfd);
    SSL_CTX_free(ctx);
    close(socket);

    X509_free(pcert);
    EVP_PKEY_free(pkey);
    X509_NAME_free(subj);
    //RSA_free(rsa); 请勿释放RSA
    BN_free(big);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return env->NewStringUTF(buf);
}
