#include"UserModel.hpp"
#include<iostream>
using namespace std;
bool UserModel::insert(User&user)
{
        //1.组装sql语句
        char sql[1024]={0};
        sprintf(sql,"insert into user(name,password,state) values('%s','%s','%s')",
                        user.getName().c_str(),user.getPwd().c_str(),user.getState().c_str());             
        MySQL mysql;
        if(mysql.connect())
        {
            if(mysql.update(sql))
            {
                user.setId(mysql_insert_id(mysql.getConnection()));
                return true;
            }
        }
        return false;
}
 User UserModel::query(int id)
 {  
    //1.创建user 对象
    User user;
    //2.组装sql语句
    char sql[1024]="";
    sprintf(sql,"select *from user where id=%d",id);
    //3.连接数据库
    MySQL mysql;
    if(mysql.connect())
    {
    //4.返回数据库中查询到的res
       MYSQL_RES*res= mysql.query(sql);
       if(res)
       {    
    //5.如果res不为空 则代表数据库中有该字段，取出整行
           MYSQL_ROW row= mysql_fetch_row(res);
           if(row)
           {    
                //设置user的属性
                user.setId(atoi(row[0]));
                user.setName(row[1]);
                user.setPwd(row[2]);
                user.setState(row[3]);
                mysql_free_result(res);
                return user;
           }  
             mysql_free_result(res);
       }
    
    }
    //6.返回
    return user;
 }
 bool UserModel::UpdateState(User user)
 {
    char sql[1024]="";
    sprintf(sql,"update user set state='%s' where id=%d",user.getState().c_str(),user.getId());
     MySQL mysql;
    if(mysql.connect())
    {
        if(mysql.update(sql))
        {
            return true;
        }
    }
    return false;
 }