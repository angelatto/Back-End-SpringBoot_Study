package com.mycompany.webapp.controller;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mycompany.webapp.security.JwtUtil;

@RestController
@RequestMapping("/auth")
public class AuthController {
	private final Logger logger = LoggerFactory.getLogger(BoardsController.class);
	
	@Autowired
	private AuthenticationManager authenticationManager; // 내가 빈으로 만들어줌 

	@PostMapping("/login")
	// {"uid" : "user1", "upassword" : "12345"}
	public Map<String, String> login(@RequestBody Map<String, String> user) {
		// 인증 데이터 얻기 
		String uid = user.get("uid");
		String upassword = user.get("upassword");
		/* 
		 * 내가 생성해준 그 필터는 권한에 대한 URL 요청이 들어올 떄 -> 토큰을 검사해서 인증처리를 하는거고,,
		 * 지금은 로그인 요청이 왔을 때니까 저 필터를 거쳐온걱고, 또한 토큰이 아직은 없고,, 이제 최초 발행되는 시점이다. 
		 * 
		 * */
		logger.info(uid);
		logger.info(upassword);
		
		// 사용자 인증 
		UsernamePasswordAuthenticationToken upat = new UsernamePasswordAuthenticationToken(uid, upassword);
		Authentication authentication = authenticationManager.authenticate(upat); // 인증 요청 
		
		// Spring Security에 인증 객체 등록 
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		// JWT 생성 
		String jwt = JwtUtil.createToken(uid);
		
		// JSON 응답 보내기 
		Map<String, String> map = new HashMap<>();
		map.put("authToken", jwt);
		map.put("uid", uid);
		return map;
	}

}
