#include"chatserver.hpp"
#include<functional>
#include"chatservice.hpp"
#include"json.hpp"
using namespace std;
using namespace placeholders;
ChatServer::ChatServer(EventLoop* loop,
            const InetAddress& listenAddr,
            const string& nameArg):_server(loop,listenAddr,nameArg),_loop(loop)
{   
    //注册连接回调
    _server.setConnectionCallback(std::bind(&ChatServer::OnConnection,this,_1));
    //注册消息回调
    _server.setMessageCallback(std::bind(&ChatServer::OnMessage,this,_1,_2,_3));
    //设置线程数量
    _server.setThreadNum(4);
}
//启动服务
void ChatServer:: start()
{
    _server.start();
}
 void ChatServer:: OnConnection(const TcpConnectionPtr&conn)
 {
    //客户端断开连接
    if(!conn->connected())
    {   
        ChatService::instance()->clientCloseException(conn);
        conn->shutdown();
    }
 };
 void ChatServer::OnMessage(const TcpConnectionPtr&conn,Buffer*buffer,Timestamp time)
 {
    string buf=buffer->retrieveAllAsString();
    //数据反序列化
    json js=json::parse(buf);
    //达到目的 完全解耦网络模块的代码和业务模块的代码
    //通过js["msgid"]---->业务handler---->conn js time
    
    //回调消息绑定好的业务模块的回调函数(事件处理器),来执行相应的业务处理
    auto msgHander=ChatService::instance()->getHandler(js["msgid"].get<int>());
    msgHander(conn,js,time);
 };
