package com.example.demo.pojo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * 安全用户模型
 * @author kwq
 * @date Nov 20, 2018
 */
public class JwtUserDetails implements UserDetails {

	private static final long serialVersionUID = 1L;
    private Long id;
    private String account;
	private String username;
    private String password;
    private String salt;
    private String attPath;
    private Long deptId;
    private Collection<? extends GrantedAuthority> authorities;

   public JwtUserDetails(Long id,String attPath, String account,String username, String password, String salt, Long deptId,Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.attPath=attPath;
        this.account = account;
        this.username = username;
        this.password = password;
        this.salt = salt;
        this.deptId = deptId;
        this.authorities = authorities;
    }

    public Long getId() {
        return id;
    }
    public String getAccount() {
        return account;
    }
    public String getAttPath() {
        return attPath;
    }
    @Override
    public String getUsername() {
        return username;
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        return password;
    }

    public String getSalt() {
		return salt;
	}

    public Long getDeptId() {
        return deptId;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return true;
    }

}
