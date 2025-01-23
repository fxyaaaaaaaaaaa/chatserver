#include "friendmodel.hpp"
#include "sql_connection_pool.h"
void FriendModel::insert(int userid, int friendid)
{
    char sql[1024] = "";
    sprintf(sql, "insert into friend values(%d,%d)", userid, friendid);
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
vector<User> FriendModel::query(int userid)
{
    char sql[1024] = "";
    sprintf(sql, "select a.id,a.name,a.state from user a inner join friend b on b.friendid=a.id  where b.userid=%d", userid);
    vector<User> vec;
    MYSQL *mysql = NULL;
    connectionRAII mysqlcon(&mysql, connection_pool::GetInstance());
    if (mysql)
    {
        MYSQL_RES *res = nullptr;
        if(mysql_query(mysql,sql))
        {
             CLOG_INFO("%s:%s:%s 查询失败!",__FILE__,__LINE__,sql);
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
                User user;
                user.setId(atoi(row[0]));
                user.setName(row[1]);
                user.setState(row[2]);
                vec.push_back(user);
            }
            mysql_free_result(res);
            return vec;
        }
    }
    return vec;
};
