#ifndef PUBLIC_H
#define PUBLIC_H
/*
server 和 client的公共文件
*/
#endif
enum EnMsgType
{
    LOGIN_MSG = 1,  // 登录消息
    LOGIN_MSG_ACK,  // 登录的回复
    LOGINOUT_MSG,   // 注销消息
    REG_MSG,        // 注册消息
    REG_MSG_ACK,    // 注册的回复
    ONE_CHAT_MSG,   // 聊天消息
    ADD_FRIEND_MSG, // 添加好友

    CREATE_GROUP_MSG, // 创建群组
    ADD_GROUP_MSG,    // 加入群组
    GROUP_CHAT_MSG,   // 群聊天

    //SM加密模块
    REQ_SIGN,       //证书 签名验证
    RSP_SIGN,

    REQ_IvExchange, //加密发送IV
    RSP_IvExchange, //发送生成的SM4密钥

    REQ_EncryTest,  //SM4加密测试
    RSP_EncryTest,  //SM4加密回应
};