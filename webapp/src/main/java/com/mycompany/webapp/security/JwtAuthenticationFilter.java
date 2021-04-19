package com.mycompany.webapp.security;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.GenericFilterBean;

public class JwtAuthenticationFilter extends GenericFilterBean { // 제네릭필터빈은 추상 클래스이다.
	private UserDetailsService userDetailsService; // 사용자의 상세 정보를 가져오는 서비스 객체를 Spring 관리 객체로 등록
	
	private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
	
	// 생성자 매개변수로 UserDetailsService를 주입받았다. 
	public JwtAuthenticationFilter(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	// Http가 안붙으면 웹이 아닌 곳에서도 쓸 수 있는 서블릿 리퀘스트이다. HttpServletRequest는 웹에서만 쓸 수 있는것이다.
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// JWT 토큰이 요청 헤더로 전송된 경우
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		String jwt = httpRequest.getHeader("authToken");
		if (jwt == null) {
			// Jwt가 요청 파라미터로 전달된 경우
			// <img src="download?bno=3&authToken=xxxx"/>
			jwt = request.getParameter("authToken");
		}
		if (jwt != null) { // 얘가 실행이 안되면 인증이 안되었다는 것이다.
			if (JwtUtil.validateToken(jwt)) { // 토큰의 만료기간이 지나지 않았을 때
				// JWT 에서 uid 얻기
				String uid = JwtUtil.getUid(jwt); // uid 뽑아옴
				// DB에서 uid에 해당하는 정보를 가져오기 (이름, 권한(ROLE)들 - user이면서 admin)
				UserDetails userDetails = userDetailsService.loadUserByUsername(uid); // db에서 user 정보 가져옴

				/* 스프링 시큐리티 실행환경에 인증 성공했다는 것을 알려주기 위해 세터 실행 */
				// 인증 "성공" 객체 생성 
				Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, "",
						userDetails.getAuthorities());
				// Spring Security에 인증 객체 등록
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}
		chain.doFilter(request, response); //  그다음 필터를 실행해라 
	}

}