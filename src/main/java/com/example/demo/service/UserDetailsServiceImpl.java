package com.example.demo.service;


import com.example.demo.pojo.JwtUserDetails;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * 用户登录认证信息查询
 * @author kwq
 * @date Nov 20, 2018
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {



    @Override
    public UserDetails loadUserByUsername(String account) throws UsernameNotFoundException {

        System.out.println("自定义登录逻辑");
        // 用户权限列表，根据用户拥有的权限标识与如 @PreAuthorize("hasAuthority('sys:menu:view')") 标注的接口对比，决定是否可以调用接口

        if (account.equals("ke")){
            return new JwtUserDetails
                    (1L,"Path属性", account,
                            "username属性", "password属性",
                            "salt属性", 1L, AuthorityUtils.commaSeparatedStringToAuthorityList("admin1,normal"));
        }else
        return new JwtUserDetails
                (1L,"Path属性", account,
                        "username属性", "password属性",
                        "salt属性", 1L, AuthorityUtils.commaSeparatedStringToAuthorityList("admin,normal"));
    }
}
