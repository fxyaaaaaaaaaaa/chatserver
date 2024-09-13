#include "groupmodel.hpp"
#include "db.h"
// 创建群组
bool GroupModel::createGroup(Group &group)
{
    // 1.组装sql语句
    char sql[1024] = {0};
    sprintf(sql, "insert into allgroup(groupname,groupdesc) values('%s','%s')",
            group.getName().c_str(), group.getDesc().c_str());
    MySQL mysql;
    if (mysql.connect())
    {
        if (mysql.update(sql))
        {
            group.setId(mysql_insert_id(mysql.getConnection()));
            return true;
        }
    }
    return false;
};
// 加入群组
void GroupModel::addGroup(int userid, int groupid, string role)
{
    // 1.组装sql语句
    char sql[1024] = {0};
    sprintf(sql, "insert into groupuser values(%d,%d,'%s')",
            groupid, userid, role.c_str());
    MySQL mysql;
    if (mysql.connect())
    {
        mysql.update(sql);
    }
};
// 查询用户所在群组信息
vector<Group> GroupModel::queryGroups(int userid)
{
    /*
        1.先根据userid在groupuser表中查询出该用户所属的群组信息
        2.在根据群组信息，查询该群组的所有用户的userid，并且和user表进行夺标联合查询，查出用户详细信息。
    */
    char sql[1024] = ""; 
    sprintf(sql, "select a.id,a.groupname,a.groupdesc from allgroup a inner join groupuser \
            b on a.id=b.groupid where b.userid=%d",
            userid);
    vector<Group> groupvec;
    MySQL mysql;
    if (mysql.connect())
    {
        // 3.返回数据库中查询到的res
        MYSQL_RES *res = mysql.query(sql);
        if (res)
        {
            // 4.如果res不为空 则代表数据库中有该字段，取出整行 因为数据可能不止一行 因此循环取出
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                Group group;
                group.setId(atoi(row[0]));
                group.setName(row[1]);
                group.setDesc(row[2]);
                groupvec.push_back(group);
            }
            mysql_free_result(res);
        }
    }
    // 查询群组的用户信息
    for (Group &group : groupvec)
    {
        sprintf(sql, "select a.id,a.name,a.state,b.grouprole from user a inner join \
        groupuser b on b.userid=a.id where b.groupid=%d", group.getId());
        // 3.返回数据库中查询到的res
        MYSQL_RES *res = mysql.query(sql);
        if (res)
        {
            // 4.如果res不为空 则代表数据库中有该字段，取出整行 因为数据可能不止一行 因此循环取出
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                GroupUser user;
                user.setId(atoi(row[0]));
                user.setName(row[1]);
                user.setState(row[2]);
                user.setRole(row[3]);
                group.getUsers().push_back(user);
            }
            mysql_free_result(res);
        }
    }
    return groupvec;
};
// 根据指定的groupid查询群组用户id列表,除userid自己,主要用户群聊业务给群组其它成员群发消息
vector<int> GroupModel::queryGroupUsers(int userid, int groupid)
{
    char sql[1024] = "";
    sprintf(sql, "select userid from groupuser where groupid=%d and userid !=%d", groupid, userid);
    vector<int> idvec;
    MySQL mysql;
    if (mysql.connect())
    {
        // 3.返回数据库中查询到的res
        MYSQL_RES *res = mysql.query(sql);
        if (res)
        {
            // 4.如果res不为空 则代表数据库中有该字段，取出整行 因为数据可能不止一行 因此循环取出
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr)
            {
                idvec.push_back(atoi(row[0]));
            }
            mysql_free_result(res);
        }
    }
    return idvec;
};
