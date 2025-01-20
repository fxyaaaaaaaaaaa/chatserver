#include "chatserver.hpp"
#include <functional>
#include "chatservice.hpp"
#include "json.hpp"
using namespace std;
using namespace placeholders;
ChatServer::ChatServer(EventLoop *loop,
                       const InetAddress &listenAddr,
                       const string &nameArg) : _server(loop, listenAddr, nameArg), _loop(loop)
{
    // 注册连接回调
    _server.setConnectionCallback(std::bind(&ChatServer::OnConnection, this, _1));
    // 注册消息回调
    _server.setMessageCallback(std::bind(&ChatServer::OnMessage, this, _1, _2, _3));
    // 设置线程数量
    _server.setThreadNum(4);
}
// 启动服务
void ChatServer::start()
{
    _server.start();
}
void ChatServer::OnConnection(const TcpConnectionPtr &conn)
{
    // 客户端断开连接
    if (!conn->connected())
    {
        ChatService::instance()->clientCloseException(conn);
        conn->shutdown();
    }
};
void ChatServer::OnMessage(const TcpConnectionPtr &conn, Buffer *buffer, Timestamp time)
{

    // 保证有一个头
    while (buffer->readableBytes() >= sizeof(uint32_t))
    {
        // 窥探报文前四个字节
        uint32_t length = buffer->peekInt32();
        if (buffer->readableBytes() >= length + sizeof(uint32_t)) // 确保缓冲区里的数据足够
        {
            buffer->retrieve(sizeof(uint32_t)); // 移除长度字符串
            json js;
            try
            {
                string buf = buffer->retrieveAsString(length);
                js = json::parse(buf);
            }
            catch (const nlohmann::json::parse_error &e)
            {
                LOG_ERROR << "JSON parse error at byte " << e.byte << ": " << e.what();
                break;
                // 处理解析失败的情况，例如记录错误、返回默认值等
            }
            auto msgHander = ChatService::instance()->getHandler(js["msgid"].get<int>());
            msgHander(conn, js, time);
        }
        else
        {
            break;
        }
    }

    // 数据反序列化

    // 达到目的 完全解耦网络模块的代码和业务模块的代码
    // 通过js["msgid"]---->业务handler---->conn js time
    // 回调消息绑定好的业务模块的回调函数(事件处理器),来执行相应的业务处理
};
