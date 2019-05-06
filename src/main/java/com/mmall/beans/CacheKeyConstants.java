package com.mmall.beans;

import lombok.Getter;

@Getter
public enum CacheKeyConstants {
    //SYSTEM_ACLS缓存系统内的所有权限，USER_ACLS缓存用户的权限
    SYSTEM_ACLS,
    USER_ACLS;
}
