package com.cdfive.learning.gateway.filter.auth;

import com.cdfive.learning.gateway.util.JwtUtil;
import lombok.Getter;
import lombok.Setter;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

/**
 * JWT授权过滤器工厂
 *
 * @author cdfive
 */
@Component
public class JwtAuthGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtAuthGatewayFilterFactory.Config> {

    public JwtAuthGatewayFilterFactory() {
        super(JwtAuthGatewayFilterFactory.Config.class);
    }

    @Override
    public GatewayFilter apply(JwtAuthGatewayFilterFactory.Config config) {
        JwtUtil.init(config.getJwtSecret(), config.getAccessTokenExpire());
        return new JwtAuthGatewayFilter(config.whiteList);
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("whiteList", "jwtSecret", "accessTokenExpire");
    }

    @Getter
    @Setter
    public static class Config {
        private List<String> whiteList;

        private String jwtSecret;

        private Long accessTokenExpire;
    }
}
