#ifndef USERMODEL_H
#define USERMODEL_H
#include"db.h"
#include"user.hpp"
//user 表的数据操作类
class UserModel{
    public:
    //User表的增加方法
    bool insert(User&user);
    User query(int id);
    bool UpdateState(User user);
};
#endif