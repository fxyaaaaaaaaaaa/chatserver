#ifndef FRIENDMODEL_H
#define FRIENDMODEL_H
#include"user.hpp"
#include<vector>
class FriendModel{
public:
    void insert(int userid,int friendid);
    vector<User> query(int userid);
};
#endif