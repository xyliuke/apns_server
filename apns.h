//
// Created by liuke on 15/10/14.
//

#ifndef APNS_SERVER_APNS_H
#define APNS_SERVER_APNS_H


#include <iosfwd>
#include <string>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

class apns {
public:
    apns(std::string pem);
    ~apns();
    void connect();
    void send(std::string token, std::string payload);
    void send(std::string token, std::string body, int badge);
    void send(std::string token, std::string body, int badge, std::string sound);
    void close();

private:
    void token2bytes(std::string token, char* bytes);
    int push_msg_impl(std::string token, std::string payload);
private:
    std::string pem_file;
    SSL *ssl;
    SSL_CTX *ctx;
    const SSL_METHOD* method;
    X509 *cert;
    EVP_PKEY *key;
    BIO *bio;

    static std::string host;
};


#endif //APNS_SERVER_APNS_H
