//
// Created by liuke on 15/10/14.
//


#include <sstream>
#include "apns.h"
#ifdef __linux__
#include <arpa/inet.h>
#endif

std::string apns::host = "gateway.sandbox.push.apple.com:2195";

apns::apns(std::string pem) : pem_file(pem),
                              ssl(NULL),
                              ctx(NULL),
                              method(NULL),
                              cert(NULL),
                              key(NULL),
                              bio(NULL)
{

}

int apns::push_msg_impl(std::string token, std::string payload)
{
    char tokenBytes[32];
    char message[293];
    int msgLength;

    token2bytes(token, tokenBytes);

    unsigned char command = 0;
    size_t payloadLength = payload.length();
    char *pointer = message;
    unsigned short networkTokenLength = htons((u_short)32);
    unsigned short networkPayloadLength = htons((unsigned short)payloadLength);
    memcpy(pointer, &command, sizeof(unsigned char));
    pointer +=sizeof(unsigned char);
    memcpy(pointer, &networkTokenLength, sizeof(unsigned short));
    pointer += sizeof(unsigned short);
    memcpy(pointer, tokenBytes, 32);
    pointer += 32;
    memcpy(pointer, &networkPayloadLength, sizeof(unsigned short));
    pointer += sizeof(unsigned short);
    memcpy(pointer, payload.c_str(), payloadLength);
    pointer += payloadLength;
    msgLength = (int)(pointer - message);
    int ret = SSL_write(ssl, message, msgLength);

    return ret;
}


void apns::connect()
{
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    SSL_library_init();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (SSL_CTX_use_certificate_chain_file(ctx, pem_file.c_str()) != 1) {
        printf("Error loading certificate from file\n");
        ctx = NULL;
        return;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, pem_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        printf("Error loading private key from file\n");
        return;
    }
    bio = BIO_new_connect((char*)host.c_str());
    if (!bio) {
        printf("Error creating connection BIO\n");
        return;
    }
    if (BIO_do_connect(bio) <= 0) {
        printf("Error connection to remote machine\n");
        return;
    }
    if (!(ssl = SSL_new(ctx))) {
        printf("Error creating an SSL contexxt\n");
        return;
    }

    SSL_set_bio(ssl, bio, bio);
    int slRc = SSL_connect(ssl);
    if (slRc <= 0) {
        printf("Error connecting SSL object>>%d\n", slRc);
        return;
    }
}

void apns::send(std::string token, std::string payload)
{
    if (ssl && ctx) {
        int ret = push_msg_impl(token,payload);
    } else {
        printf("send data error");
    }
}

void apns::close()
{
    if(ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
    }
    if(ctx) {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
}

void apns::send(std::string token, std::string body, int badge)
{
    std::stringstream ss;
    ss << "{\"aps\":{\"alert\":\"";
    ss << body;
    ss << "\",\"badge\":";
    ss << badge;
    ss << ",\"sound\":\"default\"}}";
    send(token, ss.str());
}

void apns::send(std::string token, std::string body, int badge, std::string sound)
{
    std::stringstream ss;
    ss << "{\"aps\":{\"alert\":\"";
    ss << body;
    ss << "\",\"badge\":";
    ss << badge;
    ss << ",\"sound\":\"";
    ss << sound;
    ss << "\"}}";
    send(token, ss.str());
}

void apns::token2bytes(std::string token, char *bytes)
{
    int val;

    const char* token_char = token.c_str();

    while (*token_char) {
        sscanf(token_char, "%2x", &val);
        *(bytes++) = (char)val;
        token_char += 2;
        while (*token_char == ' ') {
            // skip space
            ++token_char;
        }
    }
}

apns::~apns()
{
    close();
}