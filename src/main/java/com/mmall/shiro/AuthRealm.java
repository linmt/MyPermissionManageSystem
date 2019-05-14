package com.mmall.shiro;

import com.mmall.model.SysAcl;
import com.mmall.model.SysRole;
import com.mmall.model.SysUser;
import com.mmall.service.SysCoreService;
import com.mmall.service.SysRoleService;
import com.mmall.service.SysUserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by 张洲徽 on 2019/4/25.
 */
public class AuthRealm extends AuthorizingRealm {

    @Resource
    private SysRoleService sysRoleService;
    @Resource
    private SysCoreService sysCoreService;
    @Resource
    private SysUserService sysUserService;

    //授权  当jsp页面出现shrio标签时，就会执行授权方法
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection pc) {
        System.out.println("授权");

        //根据reaml的名字去找对应的reaml
        SysUser user=(SysUser)pc.fromRealm(this.getName()).iterator().next();

        //对象导航
        List<SysRole> roles=sysRoleService.getRoleListByUserId(user.getId());
        List<String> permissions=new ArrayList<String>();

        //遍历每个角色，得到每个角色下的模块（权限）列表
        for(SysRole role:roles){
            List<SysAcl> roleAclList = sysCoreService.getRoleAclList(role.getId());
            for(SysAcl m:roleAclList){
                permissions.add(m.getName());
            }
        }
        SimpleAuthorizationInfo info=new SimpleAuthorizationInfo();
        //添加用户的模块（权限）
        info.addStringPermissions(permissions);
        return info;
    }

    //认证
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("认证");

        //向下转型
        UsernamePasswordToken upToken = (UsernamePasswordToken)token;

        //调用业务方法，实现根据用户名查询
        List<SysUser> list=sysUserService.find(upToken.getUsername());
        if(list!=null && list.size()>0){
            SysUser user=list.get(0);
            //这里为什么传user对象而不是username？？？
            AuthenticationInfo info = new SimpleAuthenticationInfo(user,user.getPassword(),this.getName());
            //此处如果返回，就会立即进入到密码比较器
            return info;
        }
        //就会出现异常
        return null;
    }
}
