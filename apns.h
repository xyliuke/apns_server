//
// Created by liuke on 15/10/14.
//

#ifndef APNS_SERVER_APNS_H
#define APNS_SERVER_APNS_H


#include <string>
#include <memory>

class apns {
	class apns_impl;
	std::shared_ptr<apns_impl> impl_;
public:
    apns(std::string pem);
    ~apns();
    void connect();
    void send(std::string token, std::string payload);
    void send(std::string token, std::string body, int badge);
    void send(std::string token, std::string body, int badge, std::string sound);
    void close();

};


#endif //APNS_SERVER_APNS_H
