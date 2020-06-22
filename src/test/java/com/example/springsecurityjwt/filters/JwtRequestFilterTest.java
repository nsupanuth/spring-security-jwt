package com.example.springsecurityjwt.filters;

import com.example.springsecurityjwt.services.MyUserDetailsService;
import com.example.springsecurityjwt.util.JwtUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Arrays;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class JwtRequestFilterTest {

    private static String MOCK_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiJ9.Q8H6k8FFS18d_P3e2ZGaTw57GA3EbUWrDZMeGMe93-mk19ldDaezGCD3ohRPvPFoOmFvZ0Xod25y1gv-FawLKAWtwuXCOE8xhx8wd4XwW72OUSqh5w2Bj0WTZg1276r2nm_2ooqrzzXxvJ_4KM-E4V4p2L9mHuZg8Pv9IGZTcuM.3uTaLLXmVhc-kCMAGqjQQSVgQfgMACyPdty7_jnbMnI";

    @InjectMocks
    @Spy
    private JwtRequestFilter jwtRequestFilter;

    @Mock
    private MyUserDetailsService userDetailsService;

    @Mock
    private JwtUtil jwtUtil;

    HttpServletRequest request;
    HttpServletResponse response;
    FilterChain chain;

    @Before
    public void setUp() {
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
    }

    @Test
    public void testDoFilterInternal() throws ServletException, IOException {
        String authorizationHeader = "Bearer "+MOCK_ACCESS_TOKEN;
        String jwt = authorizationHeader.substring(7);

        GrantedAuthority authority = new SimpleGrantedAuthority("ADMIN");
        UserDetails userDetails = new User("foo", "foo", Arrays.asList(authority));

        when(request.getHeader("Authorization")).thenReturn(authorizationHeader);
        when(jwtUtil.extractUsername(jwt)).thenReturn("foo");
        when(userDetailsService.loadUserByUsername("foo")).thenReturn(userDetails);
        when(jwtUtil.validateToken(jwt, userDetails)).thenReturn(true);

        jwtRequestFilter.doFilterInternal(request, response, chain);
    }

}
