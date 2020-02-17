package com.cdfive.learning.gateway.util;

import com.alibaba.fastjson.JSON;
import org.junit.Test;

/**
 * @author cdfive
 */
public class JwtUtilTest {

    private static String jwtSecret = "123456789";

    private static Long accessTokenExpire = 1000 * 60 * 120L;

    @Test
    public void testCreateToken() {
        JwtUtil.init(jwtSecret, accessTokenExpire);

        JwtUtil.JwtClaims claims = new JwtUtil.JwtClaims();
        claims.setUserId(1001L);
        String token = JwtUtil.createToken(claims);
        System.out.println(token);
    }

    @Test
    public void testParseToken() {
        JwtUtil.init(jwtSecret, accessTokenExpire);

        String token = "eyJhbGciOiJIUzUxMiIsInppcCI6IkRFRiJ9.eNqqViotTi3yTFGyMjQwMNRRSq0oyCxKDcnMTQWKmFoYWhobGhmZG5sa1gIAAAD__w.3q7g6lQl2-7kK5Af9PE9fWT3aZgbXZ5BgMmSZB971odAIU0QxM3W5k_JSXtp87v8uO_4UsGUzpLvNw17xAfcnA";
        JwtUtil.JwtClaims claims = JwtUtil.parseToken(token);
        System.out.println(JSON.toJSONString(claims));
    }
}
