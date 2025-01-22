#ifndef USER_H
#define USER_H
#include<string>
using namespace std;
//User 表的ORM类
class  User{
    public:
    User(int id=-1,string name="",string password="",string state="offline")
    {
        this->id=id;
        this->name=name;
        this->password=password;
        this->state=state;
    }
    void setId(int id){this->id=id;}
    void setName(string name){this->name=name;}
    void setPwd(string pwd){this->password=pwd;}
    void setState(string state){this->state=state;}
    void setSalt(string salt){this->salt=salt;}

    int getId(){return this->id;}
    string getName(){return this->name;}
    string getPwd(){return this->password;}
    string getState(){return this->state;}
    string getSalt(){return this->salt;}
    private:
     int id;
     string name;
     string password;
     string state;
     string salt;
};
#endif
