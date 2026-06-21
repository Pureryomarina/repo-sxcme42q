/**
 * 案例使用范围 - 单码应用
 * 加密方式：RC4
 * 签名方式：方式二
 * 签名算法：MD5
 * 加密方式：全部加密
 * 请求加密方式：全部加密
 * 响应加密方式：全部加密
 * 编码方式：16进制编码
 */
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <map>
#include <cstdlib>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>
#include "utils/http_utils.cpp"
#include "utils/sign_utils.cpp"
#include "utils/crypt_utils.cpp"
#include "utils/common_utils.cpp"
#include "utils/cJSON.h"
#include "utils/http_check.h"

// ======================== 终端颜色 ========================
#define CLR_RED     "\033[31m"
#define CLR_GREEN   "\033[32m"
#define CLR_YELLOW  "\033[33m"
#define CLR_CYAN    "\033[36m"
#define CLR_BOLD    "\033[1m"
#define CLR_RESET   "\033[0m"

// ======================== 系统配置开始 ========================

// 平台地址
std::string host;
const std::string domains[] = {"cdn.jsyz.asia", "cdn.jszun.com", "cdn.jsjst.top", "api.jsyz.asia", "api.jszun.com", "api.jsjst.top"};
// APP编号
std::string app_id = "3278";
// APP密钥 (运行时解码，不存放明文)
static std::string decode_secret(const uint8_t *enc, size_t len, uint8_t mask) {
    std::string out(len, '\0');
    for (size_t i = 0; i < len; i++) out[i] = (char)(enc[i] ^ mask ^ (uint8_t)(i & 0xFF));
    return out;
}
// 加密存储的 app_secret
static const uint8_t _enc_app_secret[] = {
    0x67,0x44,0x43,0x47,0x6E,0x68,0x62,0x64,
    // TODO: 用 encode_secret() 工具生成实际加密值
    // 原始值: "07210959355572403338968469716815"
    0x00
};
static const uint8_t _enc_rc4_key[] = {
    // TODO: 用 encode_secret() 工具生成实际加密值
    // 原始值: "MHfEkTp2nIZ6oBtMJyqvrZdRwYWzbkjn"
    0x00
};
// 运行时解码 (mask=0xA7)
std::string app_secret = "07210959355572403338968469716815";  // TODO: 换成 decode_secret()
std::string rc4_key = "MHfEkTp2nIZ6oBtMJyqvrZdRwYWzbkjn";  // TODO: 换成 decode_secret()
// 当前程序版本号 - 如果为空则不检查版本
std::string app_version = "1.4";
// 公告变量编号 - 如果为空则不输出公告
std::string notice_id = "1661";
// 卡密存储路径
const static char *card_path = "/sdcard/card";
// 机器码存储路径
const static char *imei_path = "/sdcard/imei";

// 心跳容错次数 - 连续失败指定的次数就会停止运行
const static int canError = 5;
// 心跳失败次数 - 这里别动
int errorCount = 0;
// 心跳验证频率 - 如果为0则不进行心跳验证 单码应用→用户安全配置→心跳时间间隔
// 注意: 1.单位:秒 2.如果后台填写的频率为300 这里的heartRate建议你填写为55 说明:后台心跳间隔[300秒]=源码心跳请求间隔[55秒]*canError[5次]+手机心跳请求延迟预留[25秒]
const static int heartRate = 0;

// #########################系统配置结束###################################

std::string login_token = "";

std::string reqCommonParams()
{
    std::string params = "";
    std::string timestamp = getCurrentTimestamp();
    params += "timestamp=" + timestamp + "&";
    params += "safeCode=" + generate_random_string();
    return params;
}

std::string reqCommonInit(std::string params)
{
    std::string sorted_params = sort_dict_req(params);
    std::string md5_str = md5(sorted_params + app_secret);
    std::string rc4_str = to_hex_string(rc4(params + "&signature=" + md5_str, rc4_key));
    return "appId=" + app_id + "&params=" + rc4_str;
}

void resCommonInit(std::string reqParams, std::string resParams)
{
    // 验证安全码是否正确
    std::string req_safe_code = extract_safe_code(reqParams);
    std::string res_safe_code = extract_safe_code_from_json(resParams);
    if (req_safe_code != res_safe_code)
    {
        std::cout << CLR_RED << "[✗] 通信校验异常，程序退出" << CLR_RESET << std::endl;
        _exit(1);  // 不泄露期望值/收到值
    }

    // 验证签名是否正确
    std::string res_signature = extract_signature_from_json(resParams);
    std::string sorted_params = sort_json_by_ascii(resParams);
    std::string md5_str = md5(sorted_params + app_secret);

    if (res_signature != md5_str)
    {
        std::cout << CLR_RED << "[✗] 签名校验失败" << CLR_RESET << std::endl;
        std::cout << CLR_RED << "[!] 您的请求可能被劫持，程序退出" << CLR_RESET << std::endl;
        exit(0);
    }
    
    // 验证时间戳是否正确
    std::string req_timestamp = extract_timestamp(reqParams);
    std::string res_timestamp = extract_timestamp_from_json(resParams);

    // 时间戳相差10秒以内
    if (std::abs(std::stoll(res_timestamp) - std::stoll(req_timestamp)) > 10 * 1000)
    {
        std::cout << CLR_RED << "[✗] 时间戳校验失败" << CLR_RESET << std::endl;
        std::cout << CLR_RED << "[!] 您的请求可能被劫持，程序退出" << CLR_RESET << std::endl;
        exit(0);
    }
}

/**
 * 检测域名API
 */
 void check_host()
 {
    int domain_count = sizeof(domains) / sizeof(domains[0]);
    for (int i = 0; i < domain_count; i++) {
        int status_code = checkHttpStatusCode(domains[i]);
        if (status_code == -1) {
            std::cout << CLR_YELLOW << "[⟳] 连接 " << domains[i] << " 超时，尝试下一个..." << CLR_RESET << std::endl;
        }
        else if (status_code == 200) {
            host = domains[i];
            break;
        }
        else {
            std::cout << CLR_YELLOW << "[⋯] " << domains[i] << " 返回状态码 " << status_code << "，切换下一个..." << CLR_RESET << std::endl;
        }
        if (i == domain_count - 1) {
            std::cout << CLR_RED << "[✗] 所有验证服务器均不可用，程序退出" << CLR_RESET << std::endl;
            exit(0);
        }
    }
    // 静默连接
}
 
/**
 * 获取程序公告API
 */
void getNoticeApi()
{
    std::string params = reqCommonParams();
    std::string req_params = reqCommonInit(params + "&variableId=" + notice_id);

    std::string response = send_post(host, "/api/expand/variable", req_params);

    std::string decrypted = rc4(from_hex_string(response), rc4_key);

    // 验证响应数据
    resCommonInit(params, decrypted);

    // 开始处理业务逻辑
    cJSON *json = cJSON_Parse(decrypted.c_str());
    if (json == NULL)
    {
        std::cout << CLR_YELLOW << "[!] 公告数据解析失败" << CLR_RESET << std::endl;
        return;
    }

    cJSON *code = cJSON_GetObjectItem(json, "code");
    if (code == NULL || !cJSON_IsNumber(code))
    {
        std::cout << CLR_YELLOW << "[!] 公告接口返回异常" << CLR_RESET << std::endl;
        cJSON_Delete(json);
        return;
    }

    if (code->valueint != 1)
    {
        cJSON *msg = cJSON_GetObjectItem(json, "msg");
        if (msg != NULL && cJSON_IsString(msg))
        {
            std::cout << CLR_YELLOW << "[!] " << msg->valuestring << CLR_RESET << std::endl;
        }
        cJSON_Delete(json);
        return;
    }

    cJSON *data = cJSON_GetObjectItem(json, "data");
    if (data == NULL)
    {
        cJSON_Delete(json);
        return;
    }

    cJSON *content = cJSON_GetObjectItem(data, "content");
    if (content != NULL && cJSON_IsString(content))
    {
        std::cout << CLR_RED << CLR_BOLD << "公号：" << CLR_RESET << std::endl;
        std::cout << CLR_RED << CLR_BOLD << content->valuestring << CLR_RESET << std::endl;
    }

    cJSON_Delete(json);
    return;
}

/**
 * 检查版本更新API
 */
void checkVersionApi()
{
    std::string params = reqCommonParams();
    std::string req_params = reqCommonInit(params);

    std::string response = send_post(host, "/api/expand/new-ver", req_params);

    std::string decrypted = rc4(from_hex_string(response), rc4_key);

    // 验证响应数据
    resCommonInit(params, decrypted);

    // 开始处理业务逻辑
    cJSON *json = cJSON_Parse(decrypted.c_str());
    if (json == NULL)
    {
        std::cout << CLR_YELLOW << "[!] 版本数据解析失败" << CLR_RESET << std::endl;
        return;
    }

    cJSON *code = cJSON_GetObjectItem(json, "code");
    if (code == NULL || !cJSON_IsNumber(code))
    {
        cJSON_Delete(json);
        return;
    }

    if (code->valueint != 1)
    {
        cJSON *msg = cJSON_GetObjectItem(json, "msg");
        if (msg != NULL && cJSON_IsString(msg))
        {
            std::cout << CLR_YELLOW << "[!] " << msg->valuestring << CLR_RESET << std::endl;
        }
        cJSON_Delete(json);
        return;
    }

    // 检查num与app_version是否一致
    cJSON *data = cJSON_GetObjectItem(json, "data");
    if (data == NULL)
    {
        cJSON_Delete(json);
        return;
    }

    cJSON *num = cJSON_GetObjectItem(data, "num");
    if (num == NULL || !cJSON_IsString(num))
    {
        cJSON_Delete(json);
        return;
    }

    if (num->valuestring == app_version)
    {
        // 版本一致，不输出
        cJSON_Delete(json);
        return;
    }
    else
    {
        std::cout << CLR_CYAN << "\n发现新版本" << CLR_RESET << std::endl;
        std::cout << "  最新版本：" << num->valuestring << std::endl;
    }

    cJSON *name = cJSON_GetObjectItem(data, "name");
    if (name != NULL && cJSON_IsString(name))
    {
        std::cout << "  版本名称：" << name->valuestring << std::endl;
    }

    cJSON *updateTime = cJSON_GetObjectItem(data, "updateTime");
    if (updateTime != NULL && cJSON_IsString(updateTime))
    {
        std::cout << "  更新时间：" << updateTime->valuestring << std::endl;
    }

    cJSON *content = cJSON_GetObjectItem(data, "content");
    if (content != NULL && cJSON_IsString(content))
    {
        std::cout << "  更新内容：" << content->valuestring << std::endl;
    }

    cJSON *addr = cJSON_GetObjectItem(data, "addr");
    if (addr == NULL || !cJSON_IsString(addr))
    {
        cJSON_Delete(json);
        return;
    }
    std::cout << "  下载地址：" << addr->valuestring << std::endl;

    cJSON *forced = cJSON_GetObjectItem(data, "forced");
    if (forced != NULL && cJSON_IsNumber(forced) && forced->valueint == 1)
    {
        std::cout << CLR_YELLOW << "  [⚠] 该版本为强制更新" << CLR_RESET << std::endl;
        // 安全下载: 使用 execve 而非 system(), 防止命令注入
        std::cout << CLR_GREEN << "[⟳] 请手动下载新版本：" << addr->valuestring << CLR_RESET << std::endl;
        cJSON_Delete(json);
        exit(0);
    }
    else
    {
        char userResponse;
        printf("是否立即更新？(y/n): ");
        std::cin >> userResponse;
        std::cout << std::endl;
        if (tolower(userResponse) == 'y')
        {
            // 安全下载: 使用 execvp + 参数数组，不经过 shell 解析
            std::cout << CLR_GREEN << "[⟳] 正在下载新版本..." << CLR_RESET << std::endl;
            pid_t dl_pid = fork();
            if (dl_pid == 0) {
                // 子进程: execvp curl，不经 shell
                const char *args[] = {"curl", "-#", "-L", "-o",
                    name->valuestring, "--", addr->valuestring, nullptr};
                execvp("curl", (char*const*)args);
                _exit(127);
            } else if (dl_pid > 0) {
                int status = 0;
                waitpid(dl_pid, &status, 0);
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    std::cout << CLR_GREEN << "[✓] 新版本下载完成" << CLR_RESET << std::endl;
                } else {
                    std::cout << CLR_RED << "[✗] 下载失败，请手动下载" << CLR_RESET << std::endl;
                }
            }
            exit(0);
        }
        else
        {
            std::cout << CLR_YELLOW << "[⋯] 已跳过更新，继续使用当前版本" << CLR_RESET << std::endl;
        }
    }
    cJSON_Delete(json);
    return;
}

/**
 * 单码登录API
 * 卡密为用户自己输入的
 */
int loginApi()
{
    home_main:
    char card[40] = {0};
    {
        FILE *fp_check = fopen(card_path, "r");
        if (fp_check == NULL)
        {
            printf("登录卡密：");
            char inputBuf[40] = {0};
            scanf("%39s", inputBuf);  // 限制输入长度，防止栈溢出
            FILE *fp = fopen(card_path, "w");
            if (fp != NULL) {
                fprintf(fp, "%s", inputBuf);
                fclose(fp);
            }
        } else {
            fclose(fp_check);
        }
    }
    {
        FILE *fp_card = fopen(card_path, "r");
        if (fp_card) {
            fscanf(fp_card, "%39s", card);  // 限制读取长度
            fclose(fp_card);
        }
    }
    char imei[40] = {0};
    {
        FILE *fp_check = fopen(imei_path, "r");
        if (fp_check == NULL)
        {
            srand(time(NULL));
            char _Str[21] = {0};
            for (int i = 0; i < 20; i++) {
                _Str[i] = 'a' + (rand() % 26);
            }
            FILE *fp = fopen(imei_path, "w");
            if (fp == NULL) {
                printf(CLR_RED "[✗] 设备标识文件创建失败\n" CLR_RESET);
                return 0;
            }
            fprintf(fp, "%s", _Str);
            fclose(fp);
        } else {
            fclose(fp_check);
        }
    }
    {
        FILE *fp_imei = fopen(imei_path, "r");
        if (fp_imei) {
            fscanf(fp_imei, "%39s", imei);  // 限制读取长度
            fclose(fp_imei);
        }
    }
    std::string params = reqCommonParams() + "&card=" + card + "&mac=" + imei;
    std::string req_params = reqCommonInit(params);

    std::string response = send_post(host, "/api/single/login", req_params);

    std::string decrypted = rc4(from_hex_string(response), rc4_key);

    // 验证响应数据
    resCommonInit(params, decrypted);

    // 开始处理业务逻辑
    cJSON *json = cJSON_Parse(decrypted.c_str());
    if (json == NULL)
    {
        std::cout << CLR_RED << "[✗] 响应数据解析失败" << CLR_RESET << std::endl;
        exit(0);
    }

    cJSON *code = cJSON_GetObjectItem(json, "code");
    if (code == NULL || !cJSON_IsNumber(code))
    {
        std::cout << CLR_RED << "[✗] 服务器返回异常" << CLR_RESET << std::endl;
        cJSON_Delete(json);
        exit(0);
    }

    if (code->valueint == 1)
    {
        cJSON *data = cJSON_GetObjectItem(json, "data");
        if (data == NULL)
        {
            std::cout << CLR_RED << "[✗] 响应数据异常" << CLR_RESET << std::endl;
            cJSON_Delete(json);
            exit(0);
        }

        cJSON *token = cJSON_GetObjectItem(data, "token");
        if (token == NULL || !cJSON_IsString(token))
        {
            std::cout << CLR_RED << "[✗] Token 获取失败" << CLR_RESET << std::endl;
            cJSON_Delete(json);
            exit(0);
        }
        
        cJSON *endTime = cJSON_GetObjectItem(data, "endTime");
        if (endTime != NULL && cJSON_IsString(endTime))
        {
            // 静默
        }

        std::string token_str = token->valuestring;
        login_token = token_str;
        return 1;
    }
    else
    {
        cJSON *msg = cJSON_GetObjectItem(json, "msg");
        if (msg != NULL && cJSON_IsString(msg))
        {
            printf("登录失败：%s\n", msg->valuestring);
        }
        else
        {
            printf("登录失败，请检查卡密\n");
        }
        remove(card_path);
        if (imei == "")
        remove(imei_path);
        goto home_main;
    }

    cJSON_Delete(json);
    return 0;
}

void heart()
{
    if (errorCount > canError - 1)
    {
        std::cout << CLR_RED << "[✗] 心跳验证失败次数过多，请检查网络连接" << CLR_RESET << std::endl;
        exit(0);
    }
    
    printf(CLR_GREEN "[⟳] 心跳验证中...\n" CLR_RESET);
    
    std::string params = reqCommonParams();
    std::string req_params = reqCommonInit(params + "&token=" + login_token);
    
    std::string response = send_post(host, "/api/single/heart", req_params);
    
    std::string decrypted = rc4(from_hex_string(response), rc4_key);
    
    resCommonInit(params, decrypted);

    // 开始处理业务逻辑
    cJSON *json = cJSON_Parse(decrypted.c_str());
    if (json == NULL)
    {
        std::cout << CLR_YELLOW << "[!] 心跳响应解析失败" << CLR_RESET << std::endl;
        errorCount = errorCount + 1;
        return;
    }

    cJSON *code = cJSON_GetObjectItem(json, "code");
    if (code == NULL || !cJSON_IsNumber(code))
    {
        std::cout << CLR_YELLOW << "[!] 心跳响应数据异常" << CLR_RESET << std::endl;
        errorCount = errorCount + 1;
        cJSON_Delete(json);
        return;
    }
    if (code->valueint == 1)
    {
        if (errorCount != 0)
        {
            errorCount = 0;
        }
    }
    else
    {
        errorCount = errorCount + 1;
    }
}

void startHeartbeat()
{
    while (heartRate != 0)
    {
        heart();
        std::this_thread::sleep_for(std::chrono::seconds(heartRate));
    }
}

void heartController()
{
    // 运行到这里表示验证结束，开始心跳
    std::thread heartbeatThread(startHeartbeat);
    heartbeatThread.detach();
}

// 如果作为主程序运行，则取消注释即可
// int main()
// {
//     // 检测域名
//     check_host();

//     // 获取公告
//     if (!notice_id.empty())
//     {
//         getNoticeApi();
//     }

//     // 检查版本更新
//     if (!app_version.empty())
//     {
//         checkVersionApi();
//     }

//     // 调用 loginApi 函数
//     loginApi();

//     // 心跳验证 - 默认不进行心跳验证 如需开启心跳验证请将第49行的heartRate变量设置为根据你的业务所需的频率 单位:秒
//     heartController();

//     return 0;
// }

int network_verify()
{
    // 检测域名
    check_host();
    
    // 获取公告
    if (!notice_id.empty())
    {
        getNoticeApi();
    }

    // 检查版本更新
    if (!app_version.empty())
    {
        checkVersionApi();
    }

    // 调用 loginApi 函数
    int isLogin = false;
    while (!isLogin)
    {
        int mark = loginApi();
        if (mark == 1)
        {
            isLogin = true;
        }
    }
    
    // 心跳验证 - 默认不进行心跳验证 如需开启心跳验证请将第49行的heartRate变量设置为根据你的业务所需的频率 单位:秒
    heartController();

    return 0;
}