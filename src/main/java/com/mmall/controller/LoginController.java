package com.mmall.controller;

import com.mmall.model.SysUser;
import com.mmall.service.SysUserService;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class LoginController {

    @Resource
    private SysUserService sysUserService;

    Subject subject;

    @RequestMapping("/login.page")
    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        SysUser sysUser = sysUserService.findByKeyword(username);
        String errorMsg = "";
        //如果直接访问一个页面，发现没有登录，会跳转到登录页面，登录成功后会记住原来想访问的页面
        String ret = request.getParameter("ret");

        try {
            //1.得到Subject
            subject = SecurityUtils.getSubject();
            //2.调用登录方法
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            subject.login(token);//当这一代码执行时，就会自动跳入到AuthRealm中认证方法

            //3.登录成功时，就从Shiro中取出用户的登录信息
            SysUser user = (SysUser) subject.getPrincipal();

            //4.将用户放入session域中
            request.getSession().setAttribute("user", sysUser);

            if (StringUtils.isNotBlank(ret)) {
                response.sendRedirect(ret);
                //报异常的原因是重复转发或者重定向了请求，如果有多个转发或者重定向，需要在每个转发或者重定向请求之后加上return语句(最后一个请求转发或者重定向不需要加return)
                return;
            } else {
                response.sendRedirect("/admin/index.page");
                return;
            }
        } catch (Exception e) {
//            e.printStackTrace();
            errorMsg = "对不起，用户名或密码错误！";
            request.setAttribute("error", errorMsg);
            request.setAttribute("username", username);
            if (StringUtils.isNotBlank(ret)) {
                request.setAttribute("ret", ret);
            }
            String path = "signin.jsp";
            request.getRequestDispatcher(path).forward(request, response);
        }
    }

    @RequestMapping("/logout.page")
    public void logout(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        request.getSession().invalidate();
        subject.logout();
        String path = "signin.jsp";
        response.sendRedirect(path);
    }
}
