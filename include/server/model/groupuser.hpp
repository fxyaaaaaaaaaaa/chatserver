#ifndef GROUPUSER_H
#define GROUPUSER_H
#include"user.hpp"
//群组多加入成员 具有普通用户的所有属性 以及在群组中的role
class GroupUser:public User{
public:
    void setRole(string role){this->role=role;}
    string getRole(){return role;}
    private:
    string role;
};
#endif