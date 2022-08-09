package com.example.demo;

import com.example.demo.service.UserDetailsServiceImpl;
import com.example.demo.util.JwtTokenUtils;
import com.example.demo.util.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录认证过滤器
 *
 * @author kwq
 * @date Nov 20, 2018
 */

public class JwtAuthenticationFilter extends BasicAuthenticationFilter {

    @Autowired
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 获取token, 并检查登录状态
        try {
            System.out.println("过滤器拦截判断是否携带token");
           //获取接口路径
            String path = request.getRequestURI();
           if ("/login".equals(path)){
               chain.doFilter(request, response);
               return;
           }
        //判断token是否过期
            SecurityUtils.checkAuthentication(request);
            String account = JwtTokenUtils.getUsernameFromToken(JwtTokenUtils.getToken(request));
            UserDetails userDetails = new UserDetailsServiceImpl().loadUserByUsername(account);
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            //将authentication放入SecurityContextHolder中
            SecurityContextHolder.getContext().setAuthentication(authentication);



        } catch (Exception e) {
            e.printStackTrace();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
            return;
        }

        chain.doFilter(request, response);
    }

}
