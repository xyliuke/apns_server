#include <iostream>
#include "apns.h"

using namespace std;

int main() {
    std::string token = "37c364480364f3d3418244598ba3c9010cdfddbca8704620713b15949e19757a";
    std::string payload = "{\"aps\":{\"alert\":\"Hello world!!! message from c++\",\"badge\":1}}";
    apns a("./apple_push_notification_production.pem");
//    a.send(token, payload);
    a.send(token, "hello world", 100);
    sleep(1);
    a.send(token, "hello world 1", 100);
    sleep(1);
    a.send(token, "hello world 2", 100);

    return 0;
}