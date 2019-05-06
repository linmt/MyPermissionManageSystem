package com.mmall.controller;

import com.mmall.common.ApplicationContextHelper;
import com.mmall.common.JsonData;
import com.mmall.dao.SysAclModuleMapper;
import com.mmall.exception.ParamException;
import com.mmall.exception.PermissionException;
import com.mmall.model.SysAclModule;
import com.mmall.param.TestVo;
import com.mmall.util.BeanValidator;
import com.mmall.util.JsonMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.MapUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

@Controller
@RequestMapping("/test")
@Slf4j
public class TestController {

//    @RequestMapping("/hello")
//    @ResponseBody
//    public String hello() {
//        log.info("hello");
//        return "hello,permission";
//    }

    @RequestMapping("/hello.json")
    @ResponseBody
    public JsonData hello() {
        log.info("hello");
        throw new PermissionException("test exception");
//         return JsonData.success("hello, permission");
//        throw new RuntimeException("test RuntimeException");
    }

    @RequestMapping("/hellopage.page")
    @ResponseBody
    public JsonData hellopage() {
        log.info("hellopage");
//         return JsonData.success("hello, permission");
        throw new RuntimeException("test RuntimeException");
    }

    /*
    http://localhost:8080/test/validate.json
    2019-02-16 17:13:08.111 ["http-apr-8080"-exec-3] INFO  com.mmall.controller.TestController - validate
    2019-02-16 17:13:08.830 ["http-apr-8080"-exec-3] INFO  com.mmall.controller.TestController - msg->不能为空
    2019-02-16 17:13:08.831 ["http-apr-8080"-exec-3] INFO  com.mmall.controller.TestController - id->不能为null

    http://localhost:8080/test/validate.json?id=1&msg=hello
    2019-02-16 17:17:51.075 ["http-apr-8080"-exec-7] INFO  com.mmall.controller.TestController - validate
     */
    @RequestMapping("/validate.json")
    @ResponseBody
    public JsonData validate(TestVo vo) {
        log.info("validate");
        try {
            Map<String,String> map=BeanValidator.validateObject(vo);
            if(map!=null&&map.entrySet().size()>0){
                for(Map.Entry<String,String> entry:map.entrySet()){
                    log.info("{}->{}",entry.getKey(),entry.getValue());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return JsonData.success("test validate");
    }

    /*
    http://localhost:8080/test/validate.json
    {"ret":false,"msg":"{msg=不能为空, str=不能为空, id=不能为null}","data":null}

    2019-03-10 22:37:19.754 [http-nio-8080-exec-13] INFO  org.hibernate.validator.internal.util.Version - HV000001: Hibernate Validator 5.2.4.Final
    2019-03-10 22:37:21.766 [http-nio-8080-exec-13] INFO  com.mmall.common.HttpInterceptor - request start. url:/test/validate.json, params:{}
    2019-03-10 22:37:21.832 [http-nio-8080-exec-13] INFO  com.mmall.controller.TestController - validate
    2019-03-10 22:37:22.290 [http-nio-8080-exec-13] INFO  com.mmall.common.HttpInterceptor - request completed. url:/test/validate.json, cost:524
     */
//    @RequestMapping("/validate.json")
//    @ResponseBody
//    public JsonData validate(TestVo vo) throws ParamException {
//        log.info("validate");
//        BeanValidator.check(vo);
//        return JsonData.success("test validate");
//    }

    //http://localhost:8080/test/validate.json?id=1&msg=hello
//    @RequestMapping("/validate.json")
//    @ResponseBody
//    public JsonData validate(TestVo vo) throws ParamException {
//        log.info("validate");
//        SysAclModuleMapper moduleMapper = ApplicationContextHelper.popBean(SysAclModuleMapper.class);
//        SysAclModule module = moduleMapper.selectByPrimaryKey(1);
//        log.info(JsonMapper.obj2String(module));
//        BeanValidator.check(vo);
//        return JsonData.success("test validate");
//    }
}
