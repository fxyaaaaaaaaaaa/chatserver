#include "offlinemessagemodel.hpp"
#include "sql_connection_pool.h"
// 存储用户的离线消息
void OfflineMsgModel::insert(int userid, string msg)
{
    char sql[1024] = "";
    sprintf(sql, "insert into offlinemessage values(%d,'%s')", userid, msg.c_str());
    MYSQL *mysql = NULL;
    connectionRAII mysqlcon(&mysql, connection_pool::GetInstance());
    if (mysql)
    {
        if (mysql_query(mysql, sql))
        {
            CLOG_INFO("%s:%s:%s 更新失败!", __FILE__, __LINE__, sql);
        }
    }
};
// 删除用户的离线消息
void OfflineMsgModel::remove(int userid)
{
    char sql[1024] = "";
    sprintf(sql, "delete from offlinemessage where userid=%d", userid);
    MYSQL *mysql = NULL;
    connectionRAII mysqlcon(&mysql, connection_pool::GetInstance());
    if (mysql)
    {
        if (mysql_query(mysql, sql))
        {
            CLOG_INFO("%s:%s:%s 更新失败!", __FILE__, __LINE__, sql);
        }
    }
};
// 查询用户的离线消息
vector<string> OfflineMsgModel::query(int userid)
{

    // 1.组装sql语句
    char sql[1024] = "";
    sprintf(sql, "select message from offlinemessage where userid=%d", userid);

    vector<string> vec;
    // 2.连接数据库
    MYSQL *mysql = NULL;
    connectionRAII mysqlcon(&mysql, connection_pool::GetInstance());

    if (mysql)
    {
        // 3.返回数据库中查询到的res
        MYSQL_RES *res = NULL;
        if (mysql_query(mysql, sql))
        {
            CLOG_INFO("%s:%s:%s 查询失败!", __FILE__, __LINE__, sql);
        }
        else
        {
            res = mysql_use_result(mysql);
        }
        if (res)
        {
            // 4.如果res不为空 则代表数据库中有该字段，取出整行 因为数据可能不止一行 因此循环取出
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                vec.push_back(row[0]);
            }
            mysql_free_result(res);
            return vec;
        }
    }
    return vec;
};
void OfflineMsgModel::resetoffline()
{
    char sql[1024] = "update user set state='offline' where state='online'";
    MYSQL *mysql = NULL;
    connectionRAII mysqlcon(&mysql, connection_pool::GetInstance());
    if (mysql)
    {
        if (mysql_query(mysql, sql))
        {
            CLOG_INFO("%s:%s:%s 更新失败!", __FILE__, __LINE__, sql);
        }
    }
    return;
};