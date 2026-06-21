#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>

// 发送HTTP请求并获取状态码
int checkHttpStatusCode(const std::string& host) {
    int sockfd;
    struct sockaddr_in serveraddr;
    socklen_t addrlen = sizeof(serveraddr);
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "socket: " << strerror(errno) << std::endl;
        return -1;
    }
    std::memset(&serveraddr, 0, addrlen);
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(80);
    struct hostent* host_ent;
    host_ent = gethostbyname(host.c_str());
    if (host_ent == NULL) {
        std::cerr << "gethostbyname: " << strerror(h_errno) << std::endl;
        close(sockfd);
        return -1;
    }
    struct in_addr ip = *((struct in_addr *)host_ent->h_addr);
    serveraddr.sin_addr = ip;
    if (connect(sockfd, (struct sockaddr *)&serveraddr, addrlen) < 0) {
        std::cerr << "connect: " << strerror(errno) << std::endl;
        close(sockfd);
        return -1;
    }
    std::string request = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    if (send(sockfd, request.c_str(), request.length(), 0) < 0) {
        std::cerr << "send: " << strerror(errno) << std::endl;
        close(sockfd);
        return -1;
    }
    char buffer[1024];
    int bytes_read = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        std::cerr << "recv: " << strerror(errno) << std::endl;
        close(sockfd);
        return -1;
    }
    buffer[bytes_read] = '\0';
    // 从响应中提取状态码
    const char* status_code_start = std::strstr(buffer, "HTTP/1.1 ");
    if (status_code_start == NULL) {
        std::cerr << "Failed to find status code" << std::endl;
        close(sockfd);
        return -1;
    }
    status_code_start += 9;
    int status_code = std::atoi(status_code_start);
    close(sockfd);
    return status_code;
}