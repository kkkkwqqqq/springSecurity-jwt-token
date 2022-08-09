package com.example.demo.util;


import com.example.demo.pojo.JwtAuthenticatioToken;
import com.example.demo.pojo.JwtUserDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import javax.servlet.http.HttpServletRequest;


/**
 * Security相关操作
 * @author kwq
 * @date Nov 20, 2018
 */
public class SecurityUtils {
	/**
	 * 系统登录认证
	 * @param request
	 * @param username
	 * @param password
	 * @param authenticationManager
	 * @return
	 */
	public static JwtAuthenticatioToken login(HttpServletRequest request, String username, String password, AuthenticationManager authenticationManager) {

		JwtAuthenticatioToken token = new JwtAuthenticatioToken(username, password);
		token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		System.out.println("下一步执行自定义逻辑=>");
		// 执行登录认证过程
	    Authentication authentication = authenticationManager.authenticate(token);
		/*authentication封装了JwtUserDetails*/
	    // 认证成功存储认证信息到上下文
	    SecurityContextHolder.getContext().setAuthentication(authentication);
		// 生成令牌并返回给客户端
	    token.setToken(JwtTokenUtils.generateToken(authentication));
		return token;
	}

	/**
	 * 获取令牌进行认证
	 * @param request
	 */
	public static void checkAuthentication(HttpServletRequest request) throws Exception {
		String token = JwtTokenUtils.getToken(request);
		if (JwtTokenUtils.isTokenExpired(token)) {
			throw new IllegalStateException("token 过期");
		}


	}

	/**
	 * 获取当前用户名
	 * @return
	 */
	public static String getAccount() {
		String account = null;
		JwtUserDetails jwtUserDetails = getJwtUserDetails();
		if(jwtUserDetails != null && jwtUserDetails.getAccount() != null){
			account = jwtUserDetails.getAccount();
		}
		return account;
	}

    /**
     * 获取用户主键
     * @return
     */
    public static Long getUserId() {
		Long id = null;
		JwtUserDetails jwtUserDetails = getJwtUserDetails();
		if(jwtUserDetails != null && jwtUserDetails.getId() != null){
			id = jwtUserDetails.getId();
		}
		return id;
    }

	/**
	 * 获取部门ID
	 * @return
	 */
	public static Long getDeptId() {
		Long deptId = null;
		JwtUserDetails jwtUserDetails = getJwtUserDetails();
		if(jwtUserDetails != null && jwtUserDetails.getDeptId() != null){
			deptId = jwtUserDetails.getDeptId();
		}
		return deptId;
	}

	/**
	 * 获取jwt 用户详情
	 * @return
	 */
	private static JwtUserDetails getJwtUserDetails() {
		JwtUserDetails jwtUserDetails = null;
		Authentication authentication = getAuthentication();
		if(authentication != null) {
			Object principal = authentication.getPrincipal();
			if(principal != null && principal instanceof JwtUserDetails) {
				jwtUserDetails = (JwtUserDetails) principal;
			}
		}
		return jwtUserDetails;
	}
    /**
	 * 获取用户名
	 * @return
	 */
	public static String getAccount(Authentication authentication) {
        String account = null;
        if(authentication != null) {
            Object principal = authentication.getPrincipal();
            if(principal != null && principal instanceof JwtUserDetails) {
                account = ((JwtUserDetails) principal).getAccount();
            }
        }
        return account;
	}

    /**
     * 获取用户主键
     * @return
     */
    public static Long getUserId(Authentication authentication) {
        Long id = null;
        if(authentication != null) {
            Object principal = authentication.getPrincipal();
            if(principal != null && principal instanceof JwtUserDetails) {
                id = ((JwtUserDetails) principal).getId();
            }
        }
        return id;
    }

    /**
	 * 获取当前登录信息
	 * @return
	 */
	public static Authentication getAuthentication() {
		if(SecurityContextHolder.getContext() == null) {
			return null;
		}
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return authentication;
	}

}
