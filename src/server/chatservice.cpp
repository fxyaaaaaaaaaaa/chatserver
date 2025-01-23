#include "chatservice.hpp"
#include "protocol.hpp"
#include "logger.h"
#include <vector>
#include <iostream>
#include "encryption_data.hpp"
ChatService *ChatService::instance()
{
    static ChatService service;
    return &service;
};
void ChatService::login(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    string password = js["password"];
    // json 类型存储为字符串 使用get方法转为int类型
    int id = js["id"].get<int>();
    User user = _userModel.query(id);
    password = SM::getInstance().sm3_hash(password, user.getSalt());

    if (user.getId() == id && user.getPwd() == password)
    {
        // id和密码正确 并且 未在其他位置登录
        if (user.getState() == "online")
        {

            json response;
            response["msgid"] = LOGIN_MSG_ACK;
            response["errno"] = 2;
            response["errmsg"] = "this account is using, input another!";
            conn->send(response.dump());
        }
        else
        {
            // 登录成功,记录用户连接信息 lock_guard 只会在当前作用域上锁，析构自动解锁
            {
                lock_guard<mutex> lock(_connMutex);
                _userConnMap.insert({id, conn});
            }
            redis.subscribe(id);
            json response;
            response["msgid"] = LOGIN_MSG_ACK;
            response["errno"] = 0;
            response["id"] = user.getId();
            response["name"] = user.getName();
            // 登录成功更新用户状态信息 offline--->online
            user.setState("online");
            _userModel.UpdateState(user);
            vector<string> vec = _offlineMsgModel.query(id);
            if (!vec.empty())
            {
                response["offlinemsg"] = vec;
                // 读取该用户的离线消息后，把离线消息进行删除
                _offlineMsgModel.remove(id);
            }
            // 用户登录成功 将用户的好友列表进行返回
            vector<User> vec1 = _friendModel.query(id);
            if (!vec1.empty())
            {
                vector<string> vec2;
                for (User &user : vec1)
                {
                    json js;
                    js["id"] = user.getId();
                    js["name"] = user.getName();
                    js["state"] = user.getState();
                    vec2.push_back(js.dump());
                }
                response["friends"] = vec2;
            }
            // 查询用户的群组消息
            vector<Group> groupuservec = _groupModel.queryGroups(id);
            if (!groupuservec.empty())
            {
                vector<string> groupv;
                for (Group &group : groupuservec)
                {
                    json grpjson;
                    grpjson["id"] = group.getId();
                    grpjson["groupname"] = group.getName();
                    grpjson["groupdesc"] = group.getDesc();
                    vector<string> userv;
                    for (GroupUser &user : group.getUsers())
                    {
                        json js;
                        js["id"] = user.getId();
                        js["name"] = user.getName();
                        js["state"] = user.getState();
                        js["role"] = user.getRole();
                        userv.push_back(js.dump());
                    }
                    grpjson["users"] = userv;
                    groupv.push_back(grpjson.dump());
                }
                response["groups"] = groupv;
            }
            conn->send(response.dump());
        }
    }
    // 密码或者id不正确
    else
    {
        // 该用户不存在,登录失败
        json response;
        response["msgid"] = LOGIN_MSG_ACK;
        response["errno"] = 1;
        response["errmsg"] = "Id or password is invalid!";
        conn->send(response.dump());
    }
};
// 处理注册业务
void ChatService::reg(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    string name = js["name"];
    string pwd = js["password"];
    User user;
    user.setName(name);
    user.setPwd(pwd);
    bool state = _userModel.insert(user);
    if (state)
    { // 注册成功
        json response;
        response["msgid"] = REG_MSG_ACK;
        response["errno"] = 0;
        response["id"] = user.getId();
        conn->send(response.dump());
    }
    else
    {
        // 注册失败
        json response;
        response["msgid"] = REG_MSG_ACK;
        response["errno"] = 1;
        conn->send(response.dump());
    }
};
ChatService::ChatService()
{
    _msgHandlerMap.insert({LOGIN_MSG, std::bind(&ChatService::login, this, _1, _2, _3)});
    _msgHandlerMap.insert({REG_MSG, std::bind(&ChatService::reg, this, _1, _2, _3)});
    _msgHandlerMap.insert({ONE_CHAT_MSG, std::bind(&ChatService::oneChat, this, _1, _2, _3)});
    _msgHandlerMap.insert({ADD_FRIEND_MSG, std::bind(&ChatService::addfriend, this, _1, _2, _3)});

    _msgHandlerMap.insert({CREATE_GROUP_MSG, std::bind(&ChatService::creategroup, this, _1, _2, _3)});
    _msgHandlerMap.insert({ADD_GROUP_MSG, std::bind(&ChatService::addgroup, this, _1, _2, _3)});
    _msgHandlerMap.insert({GROUP_CHAT_MSG, std::bind(&ChatService::groupchat, this, _1, _2, _3)});
    _msgHandlerMap.insert({LOGINOUT_MSG, std::bind(&ChatService::loginout, this, _1, _2, _3)});

    _msgHandlerMap.insert({RSP_SIGN, std::bind(&ChatService::verify_sign, this, _1, _2, _3)});
    _msgHandlerMap.insert({RSP_IvExchange, std::bind(&ChatService::ivexchange, this, _1, _2, _3)});
    _msgHandlerMap.insert({RSP_EncryTest, std::bind(&ChatService::encry_test, this, _1, _2, _3)});
    if (redis.connect())
    {
        redis.init_notify_handler(std::bind(&ChatService::handleRedisSubscribeMessage, this, _1, _2));
    }
};
MsgHandler ChatService::getHandler(int msgid)
{
    // 记录错误日志，msgid没有对应的事件处理回调
    auto it = _msgHandlerMap.find(msgid);
    if (it == _msgHandlerMap.end())
    {
        return [=](const TcpConnectionPtr &conn, json &js, Timestamp time)
        {
            CLOG_ERROR("msgid:%d can not find handler!",msgid);
        };
    }
    else
    {
        return _msgHandlerMap[msgid];
    }
}
void ChatService::loginout(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    int userid = js["id"].get<int>();
    {
        lock_guard<mutex> lock(_connMutex);
        auto it = _userConnMap.find(userid);
        if (it != _userConnMap.end())
        {
            _userConnMap.erase(it);
        }
    }
    // 更新用户信息
    User user(userid, "", "", "offline");
    redis.unsubscribe(userid);
    _userModel.UpdateState(user);
};
void ChatService::clientCloseException(const TcpConnectionPtr &conn)
{
    User user;
    {
        lock_guard<mutex> lock(_connMutex);
        for (auto it = _userConnMap.begin(); it != _userConnMap.end(); it++)
        {
            if (it->second == conn)
            {
                // 从map表中删除用户的连接信息
                user.setId(it->first);
                redis.unsubscribe(user.getId());
                _userConnMap.erase(it);
                break;
            }
        }
    }
    if (user.getId() != -1)
    {
        user.setState("offline");
        _userModel.UpdateState(user);
    }
};
void ChatService::oneChat(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    int toid = js["toid"].get<int>();
    {
        lock_guard<mutex> lock(_connMutex);
        auto it = _userConnMap.find(toid);
        if (it != _userConnMap.end())
        {
            // toid在线进行转发消息
            it->second->send(js.dump());
            return;
        }
    }
    if (_userModel.query(toid).getState() == "online")
    {
        redis.publish(toid, js.dump());
        return;
    }
    // toid 不在线，存储离线消息
    _offlineMsgModel.insert(toid, js.dump());
    return;
};
void ChatService::reset()
{
    _offlineMsgModel.resetoffline();
};
void ChatService::addfriend(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    int userid = js["id"].get<int>();
    int friendid = js["friendid"].get<int>();
    _friendModel.insert(userid, friendid);
};
void ChatService::creategroup(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    Group group;
    int id = js["id"].get<int>();
    string name = js["groupname"];
    string desc = js["groupdesc"];
    group.setId(id);
    group.setName(name);
    group.setDesc(desc);
    if (_groupModel.createGroup(group))
    {
        // 创建者放入群组中
        _groupModel.addGroup(id, group.getId(), "creator");
    };
};
void ChatService::addgroup(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    int userid = js["id"].get<int>();
    int groupid = js["groupid"].get<int>();
    _groupModel.addGroup(userid, groupid, "normal");
};
void ChatService::groupchat(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    int userid = js["id"].get<int>();
    int groupid = js["groupid"].get<int>();
    vector<int> group_user_id = _groupModel.queryGroupUsers(userid, groupid);
    lock_guard<mutex> lock(_connMutex);
    for (int i = 0; i < group_user_id.size(); i++)
    {
        auto it = _userConnMap.find(group_user_id[i]);
        if (it != _userConnMap.end())
        { // 转发群消息
            it->second->send(js.dump());
        }
        else if (_userModel.query(group_user_id[i]).getState() == "online")
        {
            redis.publish(group_user_id[i], js.dump());
        }
        else
        {
            // 存储离线消息
            _offlineMsgModel.insert(group_user_id[i], js.dump());
        }
    }
};
void ChatService::handleRedisSubscribeMessage(int userid, string msg)
{
    json js = json::parse(msg.c_str());
    lock_guard<mutex> lock(_connMutex);
    auto it = _userConnMap.find(userid);
    if (it != _userConnMap.end())
    {
        it->second->send(js.dump());
        return;
    }
    // 存储用户离线消息
    _offlineMsgModel.insert(userid, js.dump());
}
void ChatService::verify_sign(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    // 判断CA证书是否正确，验证签名。  如果不正确则直接false
    bool ret = false;
    gmssl_helper gmssl;
    FILE *cert_fp = nullptr;
    vector<unsigned char> cer = js["zh"].get<vector<unsigned char>>(); // 获取证书
    vector<unsigned char> sign = js["signed"].get<vector<unsigned char>>();
    vector<unsigned char> r1 = js["r1"].get<vector<unsigned char>>();
    vector<unsigned char> s_data(cer);
    vector<unsigned char> r(1024, 0);

    json responsejs;
    s_data.insert(s_data.end(), r1.begin(), r1.end());
    do
    {
        if (cer.size() == 0 || sign.size() == 0)
        {

            break;
        }
        cert_fp = fmemopen(cer.data(), cer.size(), "r");
        if (cert_fp == nullptr)
        {
            break;
        }
        ret = gmssl.check_cert_validity(cert_fp);
        if (!ret)
        {
            break;
        }
        ret = gmssl.gm_sm2_verify_sign(sign.data(), sign.size(), s_data.data());
        if (!ret)
        {
            CLOG_ERROR("sign error.");
            break;
        }
        SM2_KEY local_key = {0};
        uint8_t local_random[8] = {0};
        gmssl.init_local_key(&local_key);
        gmssl.set_remote_random(r1.data(), local_random);
        memcpy(r.data(), local_random, 8);
        memcpy(r.data() + 8, &local_key.public_key, sizeof(local_key.public_key));
        vector<unsigned char> out_data(1024, 0);
        size_t en_len = 0;
        ret = gmssl.gm_sm2_encrypt(r.data(), 8 + sizeof(local_key), out_data.data(), &en_len);
        if (!ret)
        {
            printf("sm2 encrypt error.");
            break;
        }
        vector<unsigned char> res(out_data.data(), out_data.data() + en_len);
        responsejs["en_msg"] = res;
        ret = true;

    } while (false);
    if (cert_fp)
    {
        fclose(cert_fp);
    }
    responsejs["msgid"] = RSP_SIGN;
    responsejs["error"] = !ret;
    conn->send(responsejs.dump());
    if (!ret)
    {
        conn->shutdown();
    }
    else
    {
        cipher.insert({conn->name(), gmssl});
    }

    // 如果CA可以那么就加入到cipher里 并且生成SM2的公私钥和R1(XOR) 并用对端的公钥加密R1和公钥发送
}
// 发送SM2密钥
void ChatService::ivexchange(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    // 解密 IV 生成 SM4密钥发送给对端
    bool ret = false;
    vector<unsigned char> encode_iv = js["encode_iv"].get<vector<unsigned char>>(); // 获取证书
    vector<unsigned char> sign = js["signed"].get<vector<unsigned char>>();
    vector<unsigned char> en_data(100);
    vector<unsigned char> iv_data(100, 0);
    vector<unsigned char> clear_data(1024, 0);
    json responsejs;
    do
    {
        if (cipher.find(conn->name()) == cipher.end())
        {
            CLOG_ERROR("未进行认证的请求");
            break;
        }
        gmssl_helper &gmssl = cipher[conn->name()];
        ret = gmssl.gm_sm2_verify_sign(encode_iv.data(), encode_iv.size(), sign.data());
        if (!ret)
        {
            CLOG_ERROR("sign error.");
            break;
        }
        size_t iv_de_len = 0;
        ret = gmssl.gm_sm2_decrypt(encode_iv.data(), encode_iv.size(), iv_data.data(), &iv_de_len);
        if (!ret || iv_de_len != 16)
        {
            CLOG_ERROR("sm2 decrypt error.");
            break;
        }
        gmssl.set_sm4_iv(iv_data.data());
        // SM4密码
        rand_bytes(clear_data.data(), 16);
        // 存储SM4密码
        gmssl.set_sm4_pswd(clear_data.data());
        size_t pswd_en_len = 0;
        ret = gmssl.gm_sm2_encrypt(clear_data.data(), 16, en_data.data(), &pswd_en_len);
        if (!ret)
        {
            CLOG_ERROR("sm2 encrypt error.");
            break;
        }
        vector<unsigned char> en_code_s(en_data.data(), en_data.data() + pswd_en_len);
        ret = true;
        responsejs["encode_test"] = en_code_s;
    } while (false);
    responsejs["msgid"] = RSP_IvExchange;
    responsejs["error"] = !ret;
    conn->send(responsejs.dump());
    if (!ret)
    {
        conn->shutdown();
        cipher.erase(conn->name());
    }
};
// 加密测试
void ChatService::encry_test(const TcpConnectionPtr &conn, json &js, Timestamp time)
{
    // 解密 IV 生成 SM4密钥发送给对端
    bool ret = false;
    vector<unsigned char> encode_test = js["encode_test"].get<vector<unsigned char>>(); // 获取证书
    vector<unsigned char> sign = js["signed"].get<vector<unsigned char>>();
    vector<unsigned char> decode_test(16, 0);
    size_t encode_len = 0;
    json responsejs;
    do
    {
        if (cipher.find(conn->name()) == cipher.end())
        {
            CLOG_ERROR("未进行认证的请求");
            break;
        }
        gmssl_helper &gmssl = cipher[conn->name()];
        ret = gmssl.gm_sm2_verify_sign(encode_test.data(), encode_test.size(), sign.data());
        if (!ret)
        {
            CLOG_ERROR("sign error.");
            break;
        }
        uint8_t store_random[16] = {0};
        gmssl.get_store_random(store_random); // 取出存储的随机数
        ret = gmssl.gm_sm2_decrypt(encode_test.data(), encode_test.size(), decode_test.data(), &encode_len);
        if (!ret || memcmp(decode_test.data(), store_random, 16) != 0)
        {
            CLOG_INFO("sm4 decrypt error.");
            break;
        }
        ret = true;
    } while (false);
    responsejs["msgid"] = RSP_EncryTest;
    responsejs["error"] = !ret;
    conn->send(responsejs.dump());
    if (!ret)
    {
        conn->shutdown();
        cipher.erase(conn->name());
    }
};