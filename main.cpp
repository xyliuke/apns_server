#include <iostream>
#include "apns.h"

using namespace std;

int main() {
    std::string token = "37c364480364f3d3418244598ba3c9010cdfddbca8704620713b15949e19757a";
    std::string payload = "{\"aps\":{\"alert\":\"Hello world!!! message from c++\",\"badge\":1}}";
    apns a("./apple_push_notification_production.pem");
    a.connect();
    a.send(token, "hello world xxxxxx bbbbbbbb", 1);
    sleep(1);
    a.send(token, "hello world xxxxxx", 1);
    a.close();

    return 0;
}