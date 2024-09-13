    #include"offlinemessagemodel.hpp"
    #include"db.h"
    //存储用户的离线消息
    void OfflineMsgModel::insert(int userid,string msg)
    {
            char sql[1024]="";
            sprintf(sql,"insert into offlinemessage values(%d,'%s')",userid,msg.c_str());
            MySQL mysql;
            if(mysql.connect())
            {
                mysql.update(sql);
            }
    };
    //删除用户的离线消息
    void OfflineMsgModel::remove(int userid)
    {
        char sql[1024]="";
            sprintf(sql,"delete from offlinemessage where userid=%d",userid);
            MySQL mysql;
            if(mysql.connect())
            {
                mysql.update(sql);
            }
    };
    //查询用户的离线消息
    vector<string> OfflineMsgModel::query (int userid)
    {
            
        //1.组装sql语句
        char sql[1024]="";
        sprintf(sql,"select message from offlinemessage where userid=%d",userid);
       
        vector<string>vec;
        //2.连接数据库
        MySQL mysql;
       
        if(mysql.connect())
    {
        //3.返回数据库中查询到的res
        MYSQL_RES*res= mysql.query(sql);
        if(res)
        {    
        //4.如果res不为空 则代表数据库中有该字段，取出整行 因为数据可能不止一行 因此循环取出
            MYSQL_ROW row;
            while((row=mysql_fetch_row(res))!=nullptr)
            {    
                 vec.push_back(row[0]);  
            }  
                mysql_free_result(res);
                return vec;
        }
    }
        return vec;
};
void OfflineMsgModel:: resetoffline()
{
    char sql[1024]="update user set state='offline' where state='online'";
     MySQL mysql;
     if(mysql.connect()){
        mysql.update(sql);
     }
     return ;
};