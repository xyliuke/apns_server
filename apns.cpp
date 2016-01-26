//
// Created by liuke on 15/10/14.
//


#include "apns.h"
#include <sstream>
#include <openssl/ssl.h>

#ifdef __linux__
#include <arpa/inet.h>
#endif
static const std::string dev_host= "gateway.sandbox.push.apple.com:2195";//开发服务器
static const std::string host= "gateway.push.apple.com:2195";//生产服务器

class apns::apns_impl
{
public:
	apns_impl(std::string pem):pem_file(pem),
		ssl(NULL),
		ctx(NULL),
		method(NULL),
		cert(NULL),
		key(NULL),
		bio(NULL){}
	std::string pem_file;
	SSL *ssl;
	SSL_CTX *ctx;
	const SSL_METHOD* method;
	X509 *cert;
	EVP_PKEY *key;
	BIO *bio;
private:
	void token2bytes(std::string token, char *bytes)
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
public:
	int push_msg_impl(std::string token, std::string payload)
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
	void connect()
	{
		SSL_load_error_strings();
		ERR_load_BIO_strings();
		OpenSSL_add_all_algorithms();
	
		SSL_library_init();
		ctx = SSL_CTX_new(SSLv23_client_method());

        char pw[] = "shmily";

        SSL_CTX_set_default_passwd_cb_userdata(ctx, pw);

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
            printf("Error connecting SSL object>>\n");
			return;
		}
	}
	int send(std::string token, std::string payload)
	{
		if (ssl && ctx) {
			int ret = push_msg_impl(token,payload);
			return ret;
		} else {
            printf("not init apns");
			return -1;
		}
	}
	void close()
	{
		if(ssl) {
			SSL_shutdown(ssl);
			SSL_free(ssl);
			ssl = NULL;
		}
		if(bio)
		{
			 BIO_free(bio);
			 bio = NULL;
		}
		if(ctx) {
			SSL_CTX_free(ctx);
			ctx = NULL;
		}
	}

};

apns::apns(std::string pem) : impl_(new apns::apns_impl(pem))
{

}

void apns::connect()
{
	impl_->connect();
}

void apns::send(std::string token, std::string payload)
{
	int ret = impl_->send(token, payload);
	if(ret==-1)
	{
		std::string pem_file = impl_->pem_file;
		impl_->close();
		impl_.reset(new apns::apns_impl(pem_file));
		impl_->connect();
		ret = impl_->send(token, payload);
		if(ret==-1)
		{
            printf("send data failed");
		}
	}
}

void apns::close()
{
	impl_->close();
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

apns::~apns()
{
    close();
}