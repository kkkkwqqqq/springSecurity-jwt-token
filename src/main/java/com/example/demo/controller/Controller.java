package com.example.demo.controller;

import com.example.demo.pojo.JwtAuthenticatioToken;
import com.example.demo.util.JwtTokenUtils;
import com.example.demo.util.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class Controller {
    @Autowired
    private AuthenticationManager authenticationManager;


    /**
     * 登录接口
     */
    @PostMapping(value = "/login")
    public String login( String account,String password, HttpServletRequest request)  throws Exception {

        // 系统登录认证
        JwtAuthenticatioToken token = SecurityUtils.login
                (request, account,password, authenticationManager);
        String token1 = token.getToken();

        return token.getToken();
    }

    @RequestMapping("/yanzheng")
    @PreAuthorize("hasAnyAuthority('admin')")
    public String yanZheng(HttpServletRequest request) throws Exception {
        String account = JwtTokenUtils.getUsernameFromToken(JwtTokenUtils.getToken(request));
        System.out.println(account);



        return account;
    }



}
