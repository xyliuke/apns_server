# apns_server 简介
apns_server是一个简单的向苹果的APNS服务器发送PUSH消息的功能，为C++版本，内置了openssl库。也可以用于测试您自己的push证书是否生成正确（这是一个新手容易出错的地方）。
apns_server是使用Clion来管理工程，导入工程可使用。在main函数中有使用例子，添加自己需要的pem证书文件，向指定token发送内容即可。
