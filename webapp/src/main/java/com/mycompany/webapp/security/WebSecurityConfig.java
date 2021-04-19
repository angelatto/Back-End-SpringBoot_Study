package com.mycompany.webapp.security;

import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);
	
	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private UserDetailsService userDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception{	
	     //security.xml에서 ROLE에따라 페이지 설정하는부분
		// 폼 인증을 비활성화 
		http.httpBasic().disable();
		// 서버 세션 비활성화 
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		// 사이트간 요청 위조 방지 
		http.csrf().disable();
		// CORS 설정 (다른 도메인에서 요청을 하기)
		http.cors(); // 너는 밑에 있는 CorsConfigurationSource 객체가 생성된 후에 설정에 따라 실행 
		// JWT 인증 필터 추가 , 특정 필터 앞 뒤로 설정 
		http.addFilterBefore(new JwtAuthenticationFilter(userDetailsService) ,UsernamePasswordAuthenticationFilter.class); // 기준 필터, 삽입할 필터 => 인증이 되고난 이후에 
		
		// 요청 경로 권한 설정 
		http.authorizeRequests()
			// 권한 계층 설정 
			.expressionHandler(securityExpressionHandler())
			// 요청 경로 권한 설정 
			.antMatchers(HttpMethod.POST, "/boards").hasAnyRole("USER")
			.antMatchers(HttpMethod.PUT, "/boards").hasAnyRole("USER")
			.antMatchers(HttpMethod.DELETE, "/boards/*").hasAnyRole("USER")
			
			.antMatchers(HttpMethod.POST, "/products").hasAnyRole("ADMIN")
			.antMatchers(HttpMethod.PUT, "/products").hasAnyRole("ADMIN")
			.antMatchers(HttpMethod.DELETE, "/products/*").hasAnyRole("ADMIN")

			// 그 이외의 모든 경로 허가 
			.antMatchers("/**").permitAll(); // 하위 경로 모두 
//			.antMatchers("/boards/**")
//			.hasAnyRole("USER");
		
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication()
        .dataSource(dataSource)
        .usersByUsernameQuery("select userid as username, userpassword as password, userenabled as enabled from users where userid=?")
        .authoritiesByUsernameQuery("select userid as username, userauthority as authority from users where userid=?")
        .passwordEncoder(new BCryptPasswordEncoder());
	}
	
	// 사용자의 상세 정보를 가져오는 서비스 객체를 Spring 관리 객체로 등록 
	//=> JwtAuthenticationFilter에서 사용 
	@Bean
	@Override
	public UserDetailsService userDetailsServiceBean() throws Exception {
		return super.userDetailsServiceBean();
	}
	
	// 인증된 정보를 관리하는 객체를 Spring 관리 객체로 등록 
	//=>  JwtAuthenticationFilter 에서 사용 
	@Bean
	public AuthenticationManager anthenticationManagerBean() throws Exception{
		return super.authenticationManagerBean();
	}
	
	// 권한 계층 설정 객체 생성 
	public RoleHierarchyImpl roleHierarchyImpl() {
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_ADMIN > ROLE_MANAGER > ROLE_USER");
		return roleHierarchyImpl;
		
	}
	
	//권한 계층 객체를 이용한 웹 시큐리티 처리 객체
	public SecurityExpressionHandler<FilterInvocation> securityExpressionHandler(){	
		DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
        defaultWebSecurityExpressionHandler.setRoleHierarchy(roleHierarchyImpl());
        return defaultWebSecurityExpressionHandler;
		
	}
	
	// 중요 ------------------------------------------------------------------------
	//이 메소드와 cors 관련 부분 매우 중요하다 반드시 이해해야 한다 !~!!!!
	@Bean // 이 어노테이션을 붙이면 메소드를 자동 실행해서 리턴된 객체를 Spring 관리 객체 등록 
	public CorsConfigurationSource corsConfigurationSource(){
		CorsConfiguration configuration = new CorsConfiguration();
		// 모든 요청 사이트 허용 
		configuration.addAllowedOrigin("*");
		// 모든 요청 방식 허용 (GET, POST, PUT, DELETE)
		configuration.addAllowedMethod("*");

		/* 
		 *  이걸 왜 해야 하나?  
		 *  요청 헤더에 JWT를 받아야 하니까 -> 요청헤더를 허용해야 한다. 
		 *  모든 요청 헤더 허용 
		 * */
		configuration.addAllowedHeader("*");
		
		// 요청 헤더의 Authorization을 이용해서 사용자 인증(로그인 처리)하지 않음 
		configuration.setAllowCredentials(false);

		// URL 요청하는 모든 내용에 대해서 위 내용을 적용 
		UrlBasedCorsConfigurationSource ccs = new UrlBasedCorsConfigurationSource();
		ccs.registerCorsConfiguration("/**", configuration);
		return ccs;
	}
	
	
	
}
