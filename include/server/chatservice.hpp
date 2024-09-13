#ifndef CHATSERVICE_H
#define CHATSERVICE_H
#include<muduo/net/TcpConnection.h>
#include<unordered_map>
#include<functional>
 #include<UserModel.hpp>
 #include<mutex>
 #include"offlinemessagemodel.hpp"
 #include"friendmodel.hpp"
 #include"groupmodel.hpp"
using namespace std;
using namespace muduo;
using namespace muduo::net;
#include"json.hpp"
#include"redis.hpp"
using json=nlohmann::json;
//处理消息的事件方法回调类型
using MsgHandler=std::function<void(const TcpConnectionPtr&conn,json&js,Timestamp)>;
//聊天服务器业务类
class ChatService{
    public:
    //获取单例对象的接口函数
    static ChatService* instance();
    //处理登录业务
    void login(const TcpConnectionPtr&conn,json&js,Timestamp time);
    //处理注册业务
     void reg(const TcpConnectionPtr&conn,json&js,Timestamp time);
     //处理用户异常下线
     void clientCloseException(const TcpConnectionPtr&conn);
     //处理一对一聊天业务
     void oneChat(const TcpConnectionPtr&conn,json&js,Timestamp time);
     //服务器异常后退出 重置用户在线状态
     void reset();
     //添加好友
     void addfriend(const TcpConnectionPtr&conn,json&js,Timestamp time);
     //创建群聊
     void creategroup(const TcpConnectionPtr&conn,json&js,Timestamp time);
     //加入群聊
     void addgroup(const TcpConnectionPtr&conn,json&js,Timestamp time);
     //群聊
     void groupchat(const TcpConnectionPtr&conn,json&js,Timestamp time);
     //处理下线业务 
     void loginout(const TcpConnectionPtr&conn,json&js,Timestamp time);
     MsgHandler getHandler(int msgid);
     //Redis的回调函数
     void handleRedisSubscribeMessage(int userid,string msg);
    private:
    ChatService();
    //存储消息id以及对应的其对应的业务处理方法
    unordered_map<int,MsgHandler>_msgHandlerMap;
    //存储在线用户的通信连接
    unordered_map<int,TcpConnectionPtr>_userConnMap;
    //定义互斥锁 ,保证_userConnMap的线程安全
    mutex _connMutex;
    //数据操作对象
    UserModel _userModel;
    OfflineMsgModel _offlineMsgModel;
    FriendModel _friendModel;
    GroupModel _groupModel;
    Redis redis;
};
#endif