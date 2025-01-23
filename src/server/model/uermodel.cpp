#include "UserModel.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string.h>
#include "logger.h"
#include "encryption_data.hpp"
#include "sql_connection_pool.h"
bool UserModel::insert(User &user)
{

    bool ret = false;
    std::string salt = SM::getInstance().generate_salt(16);
    std::string hash = SM::getInstance().sm3_hash(user.getPwd(), salt);

    CLOG_INFO("sal:%s", salt);
    CLOG_INFO("hash:%s", hash);
    // 1.组装sql语句
    do
    {
        char sql[1024] = {0};
        sprintf(sql, "insert into user(name,password,state,salt) values('%s','%s','%s','%s')",
                user.getName().c_str(), hash.c_str(), user.getState().c_str(), salt.c_str());
        MYSQL *mysql = NULL;
        connectionRAII mysqlcon(&mysql, connection_pool::GetInstance());
        if (mysql)
        {
            if (mysql_query(mysql, sql))
            {
                CLOG_INFO("%s:%s:%s 更新失败!", __FILE__, __LINE__, sql);
                break;
            }
            else
            {
                user.setId(mysql_insert_id(mysql));
                ret = true;
            }
        }
    } while (false);

    return ret;
}
User UserModel::query(int id)
{
    // 1.创建user 对象
    User user;
    // 2.组装sql语句
    char sql[1024] = "";
    sprintf(sql, "select *from user where id=%d", id);
    // 3.连接数据库
    MYSQL *mysql = NULL;
    connectionRAII mysqlcon(&mysql, connection_pool::GetInstance());
    if (mysql)
    {
        // 4.返回数据库中查询到的res
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
            // 5.如果res不为空 则代表数据库中有该字段，取出整行
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row)
            {
                // 设置user的属性
                user.setId(atoi(row[0]));
                user.setName(row[1]);
                user.setPwd(row[2]);
                user.setState(row[3]);
                user.setSalt(row[4]);
                mysql_free_result(res);
                return user;
            }
            mysql_free_result(res);
        }
    }
    // 6.返回
    return user;
}
bool UserModel::UpdateState(User user)
{
    bool ret = false;
    char sql[1024] = "";
    sprintf(sql, "update user set state='%s' where id=%d", user.getState().c_str(), user.getId());
    MYSQL *mysql = NULL;
    connectionRAII mysqlcon(&mysql, connection_pool::GetInstance());
    if (mysql)
    {
        if (mysql_query(mysql, sql))
        {
            CLOG_INFO("%s:%s:%s 更新失败!", __FILE__, __LINE__, sql);
        }
        else
        {
            ret = true;
        }
    }
    return ret;
}