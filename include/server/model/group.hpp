#ifndef GROUP_H
#define GROUP_H
//一个群组具有属性：群id 群名 群组描述 以及群组中有哪些成员
#include"groupuser.hpp"
#include<vector>
#include<string>
using namespace std;
class Group{
public:
    Group(int id=-1,string name="",string desc="")
    {
        this->id=id;
        this->name=name;
        this->desc=desc;
    }
    void setId(int id){this->id=id;}
    void setName(string name){this->name=name;}
    void setDesc(string desc){this->desc=desc;}
   
    int getId(){return this->id;}
    string getName(){return this->name;}
    string getDesc(){return this->desc;}
    vector<GroupUser> &getUsers(){return this->users;}
private:
    int id;
    string name;
    string desc;
    vector<GroupUser>users;
};
#endif