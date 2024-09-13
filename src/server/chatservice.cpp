#include "chatservice.hpp"
#include "public.hpp"
#include <muduo/base/Logging.h>
#include <vector>
#include<iostream>
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
            //查询用户的群组消息
            vector<Group>groupuservec=_groupModel.queryGroups(id);
            if(!groupuservec.empty())
            {
                vector<string>groupv;
                for(Group&group:groupuservec)
                {
                    json grpjson;
                    grpjson["id"]=group.getId();
                    grpjson["groupname"]=group.getName();
                    grpjson["groupdesc"]=group.getDesc();
                    vector<string>userv;
                    for(GroupUser&user:group.getUsers())
                    {
                        json js;
                        js["id"]=user.getId();
                        js["name"]=user.getName();
                        js["state"]=user.getState();
                        js["role"]=user.getRole();
                        userv.push_back(js.dump());
                    }
                    grpjson["users"]=userv;
                    groupv.push_back(grpjson.dump());
                }
                response["groups"]=groupv;
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
     
     if(redis.connect())
     {
        redis.init_notify_handler(std::bind(&ChatService::handleRedisSubscribeMessage,this,_1,_2));
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
            LOG_ERROR << "msgid:" << msgid << "can not find handler!";
        };
    }
    else
    {
        return _msgHandlerMap[msgid];
    }
}
void ChatService::loginout(const TcpConnectionPtr&conn,json&js,Timestamp time)
{
    int userid=js["id"].get<int>();
    {
         lock_guard<mutex> lock(_connMutex);
         auto it=_userConnMap.find(userid);
         if(it!=_userConnMap.end())
         {
            _userConnMap.erase(it);
         }
    }
    //更新用户信息
    User user(userid,"","","offline");
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
    if(_userModel.query(toid).getState()=="online")
    {
        redis.publish(toid,js.dump());
        return ;
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
        auto it=_userConnMap.find(group_user_id[i]);
        if ( it != _userConnMap.end())
        {   //转发群消息
            it->second->send(js.dump());
        }
        else if(_userModel.query(group_user_id[i]).getState()=="online")
        {
            redis.publish(group_user_id[i],js.dump());
        }
        else
        {
            //存储离线消息
            _offlineMsgModel.insert(group_user_id[i],js.dump());
        }
    }
};
void ChatService::handleRedisSubscribeMessage(int userid,string msg)
{
    std::cout<<"22222222222222222222"<<endl; 
    json js=json::parse(msg.c_str());
    lock_guard<mutex> lock(_connMutex);
    auto it=_userConnMap.find(userid);
    if(it != _userConnMap.end())
    {   std::cout<<"33333"<<endl; 
        it->second->send(js.dump());
        std::cout<<"44444"<<endl; 
        return ;
    }
    //存储用户离线消息
    _offlineMsgModel.insert(userid,js.dump());
    std::cout<<"55555";
}