#定义了一个SRC_LIST变量，包含了该目录下所有的源文件
aux_source_directory(. SRC_LIST)
aux_source_directory(./db DB_LIST)
aux_source_directory(./model MODEL_LIST)
aux_source_directory(./redis REDIS_LIST)
aux_source_directory(./sm_encryption SM_LIST)
add_executable(ChatServer ${SRC_LIST} ${DB_LIST} ${MODEL_LIST} ${REDIS_LIST} ${SM_LIST})
link_directories(${PROJECT_SOURCE_DIR}/public/gmssl/lib)

#指定可执行文件链接时需要依赖的库文件
target_link_libraries(ChatServer muduo_net muduo_base  mysqlclient  hiredis pthread crypto gmssl)