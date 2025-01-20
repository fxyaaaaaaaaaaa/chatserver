#include <iostream>
#include <functional>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <atomic>
#include <semaphore.h>
#include <thread>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "group.hpp"
#include "user.hpp"
#include "protocol.hpp"
#include"gmssl-client.h"
#include "json.hpp"
using namespace std;
using json = nlohmann::json;
void global_init();
// 加密是否成功的判断
std::atomic<bool> stopFlag(false);
// 控制聊天页面程序
bool isMainMenuRunning = false;
atomic_bool global_control(false);
sem_t rwsem;
// 记录当前系统登录的用户信息
User g_currentUser;
// 记录当前登录用户的好友列表信息
vector<User> g_currentUserFriendList;
// 记录当前登录用户的群组列表信息
vector<Group> g_currentUserGroupList;
// 显示当前登录成功用户的基本信息
void showCurrentUserData();

// 接收线程
void readTaskHandler(int clientfd);
// 获取系统时间(聊天信息需要添加时间信息)
string getCurrentTime();
// 主聊天页面程序
void mainMenu(int clientfd);
// 聊天客户端程序实现,main线程用作发送线程,子线程用作接收线程

int main(int argc, char **argv)
{
    global_init();
    if (argc < 3)
    {
        cerr << "command invalidd! example: ./ChatClient 127.0.0.1 6000" << endl;
        exit(-1);
    }
    // 解析通过命令行参数传递的ip和port
    char *ip = argv[1];
    uint16_t port = atoi(argv[2]);
    // 创建client端的socket
    int clientfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == clientfd)
    {
        cerr << "socket create error " << endl;
        exit(-1);
    }

    // 填写client需要连接的server信息 ip+port
    sockaddr_in server;
    memset(&server, 0, sizeof(sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);
    // client和server进行连接
    if (connect(clientfd, (sockaddr *)&server, sizeof(sockaddr_in)))
    {
        cerr << "connect server error" << endl;
        close(clientfd);
        exit(-1);
    }
    sem_init(&rwsem, 0, 0);

std:
    thread readTask(readTaskHandler, clientfd); // pthread_Create
    readTask.detach();

    //////////////////SM算法验证阶段////////////////////////////
    bool ret = false;
    for (int i = 11; i <= 15 && !stopFlag.load(); i += 2)
    {

        switch (i)
        {
        case REQ_SIGN:
        {
            int len = gmssl_helpe::get_instance().certification_len;
            vector<UCHAR> cer(len);
            memcpy(cer.data(), gmssl_helpe::get_instance().certification, len);
            json js;
            js["msgid"] = REQ_SIGN;
            js["zh"] = cer;
            UCHAR r1[8] = "";
            gmssl_helpe::get_instance().generate_random_numbers(r1, 0);
            memcpy(gmssl_helpe::get_instance().r1, r1, sizeof(r1));
            js["r1"] = r1;

            uint8_t outbuf[64] = "";
            uint8_t message[len + 8] = "";
            memcpy(message, cer.data(), len);
            memcpy(message + len, r1, 8);
            if (!gmssl_helpe::get_instance().wa_sm2_sign_data(&gmssl_helpe::get_instance().m_ca_1_key, (uint8_t *)message, 8 + len, outbuf))
            {
                ret = false;
                printf("签名错误!\n");
                break;
            }
            js["signed"] = outbuf;
            string request = js.dump();
            uint32_t length = htonl(request.size());
            string mes(reinterpret_cast<char *>(&length), sizeof length);
            mes += request;
            len = send(clientfd, mes.c_str(), strlen(mes.c_str()) + 1, 0);
            if (len == -1)
            {
                ret = false;
                cerr << "send login msg error:" << request << endl;
                break;
            }
            ret = true;
        }
        break;

        case REQ_IvExchange:
        {

            size_t len = 0;
            // r1||R2拼接生成 iv
            UCHAR iv_value[16] = "";
            gmssl_helpe::get_instance().generate_random_numbers(iv_value, 1);
            memcpy(gmssl_helpe::get_instance().s_sm4_iv, iv_value, sizeof(iv_value));

            // 服务器公钥加密生成密文
            UCHAR out_data[130] = "";
            if (!gmssl_helpe::get_instance().gm_sm2_encrypt(iv_value, 16, out_data, &len))
            {
                ret = false;
                printf("数据加密失败\n");
                break;
            };
            vector<UCHAR> encode_iv(len);
            memcpy(encode_iv.data(), out_data, len);
            json js;
            js["msgid"] = REQ_IvExchange;
            // 创建IvExchange结构
            js["encode_iv"] = encode_iv;

            uint8_t outbuf[64] = "";
            if (!gmssl_helpe::get_instance().wa_sm2_sign_data(&gmssl_helpe::get_instance().m_ca_1_key, (uint8_t *)(encode_iv.data()), len, outbuf))
            {
                ret = false;
                printf("签名错误!\n");
                break;
            };

            js["signed"] = outbuf;
            string request = js.dump();
            uint32_t length = htonl(request.size());
            string mes(reinterpret_cast<char *>(&length), sizeof length);
            mes += request;
            len = send(clientfd, mes.c_str(), strlen(mes.c_str()) + 1, 0);
            if (len == -1)
            {
                ret = false;
                cerr << "send login msg error:" << request << endl;
                break;
            }
            ret = true;
        }
        break;

        case REQ_EncryTest:
        {
            // r1||R2拼接生成 iv
            UCHAR r1r2[16] = "";
            memcpy(r1r2, gmssl_helpe::get_instance().r1, 8);
            memcpy(r1r2 + 8, gmssl_helpe::get_instance().R2, 8);

            // sm4公钥加密生成密文
            UCHAR out_data[130] = "";
            size_t out_len = 0;

            if (!gmssl_helpe::get_instance().gm_sm4_encrypt(r1r2, sizeof(r1r2), out_data, out_len))
            {
                printf("数据加密失败\n");
                ret = false;
                break;
            };
            json js;
            vector<UCHAR> encode_t(out_len);
            memcpy(encode_t.data(), out_data, out_len);
            js["msgid"] = REQ_EncryTest;
            js["encode_test"] = encode_t;

            uint8_t outbuf[64] = "";
            if (!gmssl_helpe::get_instance().wa_sm2_sign_data(&gmssl_helpe::get_instance().m_ca_1_key, encode_t.data(), out_len, outbuf))
            {
                ret = false;
                printf("签名错误!\n");
                break;
            };

            js["signed"] = outbuf;

            string request = js.dump();
            uint32_t length = htonl(request.size());
            string mes(reinterpret_cast<char *>(&length), sizeof length);
            mes += request;
            int len = send(clientfd, mes.c_str(), strlen(mes.c_str()) + 1, 0);
            if (len == -1)
            {
                ret = false;
                cerr << "send login msg error:" << request << endl;
                break;
            }
        }
        break;
        default:
            break;

            if (!ret)
            {
                break;
            }
            sem_wait(&rwsem);
        }
        // 子线程发生错误 主线程回收资源并结束
    }
    //////////////////加密验证不通过/////////////
    if (stopFlag.load() || !ret)

    {
        close(gmssl_helpe::get_instance().sock);
        sem_destroy(&rwsem);
        exit(EXIT_FAILURE);
    }
    //////////////////验证通过////////////////////////////

    ///////////
    // main线程用于接收用户输入,负责发送数据
    for (;;)
    {
        // 显示首页的菜单 登录、注册、退出
        cout << "===========================" << endl;
        cout << "1 . login" << endl;
        cout << "2 . register" << endl;
        cout << "3 . quit" << endl;
        cout << "===========================" << endl;
        cout << "choice:";
        int choice = 0;
        cin >> choice;
        cin.get(); // 读掉缓冲区残留的回车
        switch (choice)
        {
        case 1: // login 业务
        {
            int id = 0;
            char pwd[50] = {0};
            cout << "userid:";
            cin >> id;
            cin.get(); // 读掉缓冲区残留的回车
            cout << "userpassword:";
            cin.getline(pwd, 50);
            json js;
            js["msgid"] = LOGIN_MSG;
            js["id"] = id;
            js["password"] = pwd;
            string request = js.dump();
            uint32_t length = htonl(request.size());
            string mes(reinterpret_cast<char *>(&length), sizeof length);
            mes += request;
            int len = send(clientfd, mes.c_str(), strlen(mes.c_str()) + 1, 0);
            if (len == -1)
            {
                cerr << "send login msg error:" << request << endl;
                break;
            }
            sem_wait(&rwsem);
            if (global_control)
            {
                isMainMenuRunning = true;
                mainMenu(clientfd);
            }
        }
        break;
        case 2: // register业务
        {
            char name[50] = "";
            char pwd[50] = "";
            cout << "username:";
            cin.getline(name, 50);
            cout << "userpassword:";
            cin.getline(pwd, 50);
            json js;
            js["msgid"] = REG_MSG;
            js["name"] = name;
            js["password"] = pwd;
            string request = js.dump();
            uint32_t length = htonl(request.size());
            string mes(reinterpret_cast<char *>(&length), sizeof length);
            mes += request;
            int len = send(clientfd, mes.c_str(), strlen(mes.c_str()) + 1, 0);
            if (len == -1)
            {
                cerr << "send reg msg error:" << request << endl;
            }
            else
            {
                char buffer[1024] = {0};
                len = recv(clientfd, buffer, 1024, 0);
                if (-1 == len)
                {
                    cerr << "recv reg response error" << endl;
                }
                else
                {
                    json responsejs = json::parse(buffer);
                    if (0 != responsejs["errno"].get<int>()) // 注册失败
                    {
                        cerr << name << " is already exist, register error!" << endl;
                    }
                    else // 注册成功
                    {
                        cout << name << " register success, userid is" << responsejs["id"] << ", do not forget it" << endl;
                    }
                }
            }
        }
        break;
        case 3: // 退出业务
        {
            close(clientfd);
            sem_destroy(&rwsem);
            exit(0);
        }
        default:
            cerr << "invalid input!" << endl;
            break;
        }
    }
    return 0;
}
void registerspond(json &responsejs);
void loginrespond(json &responsejs);
bool SM_1(json &responsejs);
bool SM_2(json &responsejs);
bool SM_3(json &responsejs);
// 显示当前登录成功用户的基本信息
void showCurrentUserData()
{
    cout << "========================login  user=======================" << endl;
    cout << "current login user => id:" << g_currentUser.getId() << " name: " << g_currentUser.getName() << endl;
    cout << "-------------------------friend list----------------------" << endl;
    if (!g_currentUserFriendList.empty())
    {
        for (User &user : g_currentUserFriendList)
        {
            cout << user.getId() << " " << user.getName() << " " << user.getState() << endl;
        }
    }
    cout << "--------------------------group list-----------------------" << endl;
    if (!g_currentUserGroupList.empty())
    {
        for (Group &group : g_currentUserGroupList)
        {
            cout << group.getId() << " " << group.getName() << " " << group.getDesc() << endl;
            for (GroupUser &user : group.getUsers())
            {
                cout << user.getId() << " " << user.getName() << " " << user.getState()
                     << user.getRole() << endl;
            }
        }
    }
}
// 接收线程
void readTaskHandler(int clientfd)
{

    for (;;)
    {
        bool ret = true;
        char buffer[1024] = "";
        int len = recv(clientfd, buffer, 1024, 0);
        if (-1 == len || 0 == len)
        {
            close(clientfd);
            exit(-1);
        }

        // 接收 ChatServer 转发的数据,反序列化生成json数据对象
        json js = json::parse(buffer);
        int msgtype = js["msgid"].get<int>();
        if (ONE_CHAT_MSG == msgtype)
        {
            cout << js["time"].get<string>() << " [" << js["id"] << "]" << js["name"].get<string>()
                 << " said" << js["msg"].get<string>() << endl;
            continue;
        }
        else if (GROUP_CHAT_MSG == msgtype)
        {
            cout << "群消息[" << js["groupid"].get<int>() << "]:" << js["time"].get<string>() << " [" << js["id"].get<int>() << "]"
                 << js["name"].get<string>() << " said: " << js["msg"].get<string>() << endl;
            continue;
        }
        else if (msgtype == LOGIN_MSG_ACK)
        {
            loginrespond(js);
        }
        else if (msgtype == REG_MSG_ACK)
        {
            registerspond(js);
        }
        else if (msgtype == RSP_SIGN)
        {
            if (!SM_1(js))
            {
                stopFlag = false;
                break;
            };
        }
        else if (msgtype == RSP_IvExchange)
        {
            if (!SM_2(js))
            {
                stopFlag = false;
                break;
            };
        }
        else if (msgtype == RSP_EncryTest)
        {
            if (!SM_3(js))
            {
                stopFlag = false;
                break;
            };
        }
    }
};
void registerspond(json &responsejs)
{
    if (0 != responsejs["errno"].get<int>()) // 注册失败
    {
        cerr << "name  is already exist, register error!" << endl;
    }
    else // 注册成功
    {
        cout << " name register success, userid is" << responsejs["id"] << ", do not forget it" << endl;
    }
}
void loginrespond(json &responsejs)
{

    if (0 != responsejs["errno"].get<int>()) // 登录失败
    {
        global_control = false;
        cerr << responsejs["errmsg"] << endl;
    }
    else // 登录成功
    {
        // 记录当前用户的id和name
        g_currentUser.setId(responsejs["id"].get<int>());
        g_currentUser.setName(responsejs["name"]);
        global_control = true;
        // 记录当前用户的好友列表信息,有的人没有好友有的人有好友所以需要先判断一下
        if (responsejs.contains("friends"))
        {
            // 初始化
            g_currentUserFriendList.clear();
            vector<string> vec = responsejs["friends"];
            for (string &str : vec)
            {
                json js = json::parse(str);
                User user;
                user.setId(js["id"].get<int>());
                user.setName(js["name"]);
                user.setState(js["state"]);
                g_currentUserFriendList.push_back(user);
            }
        }
        // 记录当前用户的群组列表信息
        if (responsejs.contains("groups"))
        { // 初始化
            g_currentUserGroupList.clear();

            vector<string> vec1 = responsejs["groups"];
            for (string &groupstr : vec1)
            {
                json grpjs = json::parse(groupstr);
                Group group;
                group.setId(grpjs["id"].get<int>());
                group.setName(grpjs["groupname"]);
                group.setDesc(grpjs["groupdesc"]);

                vector<string> vec2 = grpjs["users"];
                for (string &userstr : vec2)
                {
                    GroupUser user;
                    json js = json::parse(userstr);
                    user.setId(js["id"].get<int>());
                    user.setName(js["name"]);
                    user.setState(js["state"]);
                    user.setRole(js["role"]);
                    group.getUsers().push_back(user);
                }
                g_currentUserGroupList.push_back(group);
            }
        }
        // 显示登录用户的基本信息
        showCurrentUserData();

        // 显示当前用户的离线消息 个人聊天消息或者群组消息
        if (responsejs.contains("offlinemsg"))
        {
            vector<string> vec = responsejs["offlinemsg"];
            for (string &str : vec)
            {
                json js = json::parse(str);
                // time + [id] + name + "said :"
                if (ONE_CHAT_MSG == js["msgid"].get<int>())
                {
                    cout << js["time"].get<string>() << " [" << js["id"] << "]" << js["name"].get<string>()
                         << " said" << js["msg"].get<string>() << endl;
                }
                else
                {
                    cout << "群消息[" << js["groupid"].get<int>() << "]:" << js["time"].get<string>() << " [" << js["id"].get<int>() << "]"
                         << js["name"].get<string>() << " said: " << js["msg"].get<string>() << endl;
                }
            }
        }
    }
    sem_post(&rwsem);
};
unordered_map<string, string> _commandMap =
    {
        {"help", "显示所有支持的命令,格式: help"},
        {"chat", "一对一聊天,格式: chat:friendid:message"},
        {"addfriend", "添加好友,格式: addfriend:friendid"},
        {"creategroup", "创建群组,格式: creategroup:groupname:groupdesc"},
        {"addgroup", "加入群组,格式: addgroup:groupid"},
        {"groupchat", "群聊,格式: groupchat:groupid:message"},
        {"loginout", "注销,格式: loginout"}};
void help(int a = 0, string str = "");
void chat(int, string);
void addfriend(int, string);
void creategroup(int, string);
void addgroup(int, string);
void groupchat(int, string);
void loginout(int, string);
unordered_map<string, function<void(int, string)>> commandHandlerMap =
    {
        {"help", help},
        {"chat", chat},
        {"addfriend", addfriend},
        {"creategroup", creategroup},
        {"addgroup", addgroup},
        {"groupchat", groupchat},
        {"loginout", loginout}};
// 主聊天页面程序
void mainMenu(int clientfd)
{
    help();
    char buffer[1024] = "";
    while (isMainMenuRunning)
    {
        cin.getline(buffer, 1024);
        string commandbuf(buffer);
        string command; // 存储命令
        int idx = commandbuf.find(":");
        if (idx == -1)
        {
            command = commandbuf;
        }
        else
        {
            command = commandbuf.substr(0, idx);
        }
        auto it = commandHandlerMap.find(command);
        if (it == commandHandlerMap.end())
        {
            cerr << "invalid input command!" << endl;
            continue;
        }
        // 调用相应命令的时间处理回调 对mainMenu修改封闭,添加新功能不需要修改函数
        it->second(clientfd, commandbuf.substr(idx + 1, commandbuf.size() - idx)); // 调用命令的处理方法
    }
};
void addfriend(int clientfd, string str)
{
    json js;
    js["msgid"] = ADD_FRIEND_MSG;
    js["id"] = g_currentUser.getId();
    js["friendid"] = atoi(str.c_str());
    str = js.dump();
    uint32_t length = htonl(str.size());
    string mes(reinterpret_cast<char *>(&length), sizeof length);
    mes += str;
    int len = send(clientfd, mes.c_str(), strlen(mes.c_str()) + 1, 0);
    if (len == -1)
    {
        cerr << "send addfriend error!" << endl;
    }
};
void help(int client, string str)
{
    cout << "show command list >>>" << endl;
    for (auto it = _commandMap.begin(); it != _commandMap.end(); it++)
    {
        cout << it->first << " :" << it->second << endl;
    }
    cout << endl;
};
void chat(int clientfd, string str)
{
    int idx = str.find(":");
    if (idx == -1)
    {
        cerr << "chat command invalid!" << endl;
        return;
    }
    int friendid = atoi(str.substr(0, idx).c_str());
    string message = str.substr(idx + 1, str.size() - idx);
    json js;
    js["msgid"] = ONE_CHAT_MSG;
    js["toid"] = friendid;
    js["name"] = g_currentUser.getName();
    js["id"] = g_currentUser.getId();
    js["msg"] = message;
    js["time"] = getCurrentTime();
    string buffer = js.dump();
   uint32_t length = htonl(buffer.size());
    string mes(reinterpret_cast<char *>(&length), sizeof length);
    mes += buffer;
    int len = send(clientfd, mes.c_str(), strlen(mes.c_str()) + 1, 0);
    if (len == -1)
    {
        cerr << "send addfriend error!" << endl;
    }
};
void creategroup(int clientfd, string str)
{
    int idx = str.find(":");
    if (-1 == idx)
    {
        cerr << "creategroup command invalid!" << endl;
        return;
    }
    string groupname = str.substr(0, idx);
    string groupdesc = str.substr(idx + 1, str.size() - idx);
    json js;
    js["msgid"] = CREATE_GROUP_MSG;
    js["id"] = g_currentUser.getId();
    js["groupname"] = groupname;
    js["groupdesc"] = groupdesc;
    string buffer = js.dump();
    uint32_t length = htonl(buffer.size());
    string mes(reinterpret_cast<char *>(&length), sizeof length);
    mes += buffer;
    int len = send(clientfd, mes.c_str(), strlen(mes.c_str()) + 1, 0);
    if (len == -1)
    {
        cerr << "send addfriend error!" << endl;
    }
}

void addgroup(int clientfd, string str)
{
    json js;
    js["msgid"] = ADD_GROUP_MSG;
    js["id"] = g_currentUser.getId();
    js["groupid"] = atoi(str.c_str());
    str = js.dump();
    uint32_t length = htonl(str.size());
    string mes(reinterpret_cast<char *>(&length), sizeof length);
    mes += str;
    int len = send(clientfd, mes.c_str(), strlen(mes.c_str()) + 1, 0);
    if (len == -1)
    {
        cerr << "send addfriend error!" << endl;
    }
}

void groupchat(int clientfd, string str)
{
    int idx = str.find(":");
    if (-1 == idx)
    {
        cerr << "group command invalid!" << endl;
        return;
    }

    int groupid = atoi(str.substr(0, idx).c_str());
    string message = str.substr(idx + 1, str.size() - idx);

    json js;
    js["msgid"] = GROUP_CHAT_MSG;
    js["id"] = g_currentUser.getId();
    js["name"] = g_currentUser.getName();
    js["groupid"] = groupid;
    js["msg"] = message;
    js["time"] = getCurrentTime();

    string buffer = js.dump();
    uint32_t length = htonl(buffer.size());
    string mes(reinterpret_cast<char *>(&length), sizeof length);
    mes += buffer;
    int len = send(clientfd, mes.c_str(), strlen(mes.c_str()) + 1, 0);
    if (len == -1)
    {
        cerr << "send addfriend error!" << endl;
    }
}
// 获取系统时间(聊天信息需要添加时间信息)
void loginout(int clientfd, string str)
{
    json js;
    js["msgid"] = LOGINOUT_MSG;
    js["id"] = g_currentUser.getId();
    string buffer = js.dump();

    uint32_t length = htonl(buffer.size());
    string mes(reinterpret_cast<char *>(&length), sizeof length);
    mes += buffer;
    int len = send(clientfd, mes.c_str(), strlen(mes.c_str()) + 1, 0);
    if (len == -1)
    {
        cerr << "send addfriend error!" << endl;
    }
    else
    {
        isMainMenuRunning = false;
    }
};
string getCurrentTime()
{
    auto it = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm *timeInfo = std::localtime(&it);
    std::ostringstream oss;
    oss << std::put_time(timeInfo, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}
void global_init()
{
    //////////////////////////////////////////////////////////////////////////////////
    // 加载SM初始化数据
    //  加载公钥
    if (!gmssl_helpe::get_instance().wa_load_pub_key(NULL, &gmssl_helpe::get_instance().m_ca_1_key))

    {
        printf("load client public key error!");
        exit(EXIT_FAILURE);
    };

    printf("clent public key:");
    unsigned char buf[64] = "";
    memcpy(buf, &gmssl_helpe::get_instance().m_ca_1_key.public_key, 64);

    std::ostringstream logStream;
    for (int i = 0; i < 64; i++)
    {
        logStream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buf[i]) << " ";
    }
    printf("%s", logStream.str().c_str());

    if (!gmssl_helpe::get_instance().load_certification(CA_PATH))
    {
        printf("load certification error!");
        exit(EXIT_FAILURE);
    };

    if (!gmssl_helpe::get_instance().load_private_key(SM2_PRIVATE_PATH))

    {
        printf("load sm2 private error!");
        exit(EXIT_FAILURE);
    };
}
bool SM_1(json &responsejs)
{
    printf("\n--------------------------------prase 1-------------------------------\n");


    vector<UCHAR>en_meg=responsejs["en_msg"];
    size_t out_len = 80;
    UCHAR out_data[80] = "";
    if (gmssl_helpe::get_instance().sm2_slice_decrypt(&gmssl_helpe::get_instance().m_ca_1_key, en_meg.data(), en_meg.size(), out_data, &out_len) != 1)
    {
        // printf("解密失败\n");
        return false;
    };

    UCHAR r1[8] = "";
    UCHAR R2[8] = "";
    UCHAR serv_publikey[64] = "";
    memcpy(r1, out_data, 8);
    memcpy(R2, out_data + 8, 8);
    memcpy(serv_publikey, out_data + 16, 64);
    // printf("\nR1:\n");
    for (int i = 0; i < 8; i++)
    {
        // printf("%02x ", r1[i]);
    }
    // printf("\nR2:\n");
    for (int i = 0; i < 8; i++)
    {
        // printf("%02x ", R2[i]);
    }
    // printf("\nServPubliKey:\n");
    for (int i = 0; i < 64; i++)
    {
        // printf("%02x ", ServPubliKey[i]);
    }
    // printf("\n");
    //  收到的R1和发送的不一致
    if (memcmp(r1, gmssl_helpe::get_instance().r1, 8) != 0)
    {
        // printf("r1 !=r1 数据有误！\n");

        return false;
    }
    else
    {
        // printf("r1 == r1 数据没问题!\n");
    }

    if (!gmssl_helpe::get_instance().verify_r2(R2))
    {
        // printf("\nR2 不正确\n");
        return false;
    }
    else
    {
        // printf("验证R2正确\n");
    }

    memcpy(gmssl_helpe::get_instance().R2, R2, sizeof R2);

    memcpy(&gmssl_helpe::get_instance().m_server_sm2key.public_key, serv_publikey, 64);

    return true;
};
bool SM_2(json &responsejs) {
printf("\n--------------------------------prase 2-------------------------------\n");
	


    vector<UCHAR>en_meg=responsejs["en_msg"];
	size_t out_len = 16;
	UCHAR out_data[16] = "";
	if ((gmssl_helpe::get_instance().sm2_slice_decrypt(&gmssl_helpe::get_instance().m_ca_1_key, en_meg.data(), en_meg.size(), out_data, &out_len)) != 1)
	{
		//printf("解密失败\n");
		return false;
	};

	memcpy(&gmssl_helpe::get_instance().sm4_key, out_data, 16);

	//printf("\nSm4:\n");
	for (int i = 0; i < 16; i++)
	{
		//printf("%02x ", gmssl_helpe::get_instance().sm4_key[i]);
	}

};
bool SM_3(json &responsejs) {
    printf("\n--------------------------------prase 3-------------------------------\n");
	
  
	//printf("\n");
	if (responsejs["bool"] == 1)
	{
		//printf("加密测试结束 加密通过！\n");
	}
	else
	{
		//printf("加密测试结束 加密不通过\n");
		return false;
	}

	return true;
};