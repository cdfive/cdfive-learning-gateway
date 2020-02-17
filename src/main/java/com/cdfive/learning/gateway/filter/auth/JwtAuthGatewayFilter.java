package com.cdfive.learning.gateway.filter.auth;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.cdfive.learning.gateway.util.JwtUtil;
import com.cdfive.learning.gateway.util.WebUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * JWT鉴权过滤器
 *
 * @author cdfive
 */
@Slf4j
public class JwtAuthGatewayFilter implements GatewayFilter, Ordered {

    private static final Integer AUTH_FAIL_CODE = 30002;

    private static final String AUTH_FAIL_MSG = "登录超时，请重新登录";

    private static final String HEADER_KEY_TOKEN = "Authorization";

    private static final String PARAMETER_KEY_USER_ID = "userId";

    private List<String> whiteList;

    public JwtAuthGatewayFilter(List<String> whiteList) {
        this.whiteList = whiteList;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!CollectionUtils.isEmpty(whiteList)) {
            if (whiteList.contains(exchange.getRequest().getPath().value())) {
                return chain.filter(exchange);
            }
        }

        ServerHttpRequest serverHttpRequest = exchange.getRequest();

        // 获取token
        String token = serverHttpRequest.getHeaders().getFirst(HEADER_KEY_TOKEN);
        if (StringUtils.isEmpty(token)) {
            log.error("token为空");
            return WebUtil.writeAuthFailResponse(exchange, AUTH_FAIL_CODE, AUTH_FAIL_MSG);
        }

        JwtUtil.JwtClaims jwtClaims = JwtUtil.parseToken(token);
        if (jwtClaims == null) {
            log.error("解析token失败");
            return WebUtil.writeAuthFailResponse(exchange, AUTH_FAIL_CODE, AUTH_FAIL_MSG);
        }

        Long expireTime = jwtClaims.getExpireTime();
        if (expireTime == null) {
            log.error("token中解析的过期时间为空");
            return WebUtil.writeAuthFailResponse(exchange, AUTH_FAIL_CODE, AUTH_FAIL_MSG);
        }

        long time = System.currentTimeMillis() - expireTime;
        if (time > 0) {
            log.error("token已过期");
            return WebUtil.writeAuthFailResponse(exchange, AUTH_FAIL_CODE, AUTH_FAIL_MSG);
        }

        Long tokenUserId = jwtClaims.getUserId();
        if (StringUtils.isEmpty(tokenUserId)) {
            log.error("token中解析的userId为空");
            return WebUtil.writeAuthFailResponse(exchange, AUTH_FAIL_CODE, AUTH_FAIL_MSG);
        }

        boolean authSucc = false;
        String bodyStr = WebUtil.resolveBodyFromRequest(serverHttpRequest);
        if (!StringUtils.isEmpty(bodyStr)) {
            Map<String, String> map = JSON.parseObject(bodyStr, new TypeReference<Map<String, String>>() {}.getType());
            String userId = map.get(PARAMETER_KEY_USER_ID);
            if (!StringUtils.isEmpty(userId)) {
                if (!userId.equals(tokenUserId.toString())) {
                    log.error("token和body参数中解析的userId不一致,tokenUserId={},userId={}", tokenUserId, userId);
                    return WebUtil.writeAuthFailResponse(exchange, AUTH_FAIL_CODE, AUTH_FAIL_MSG);
                } else {
                    authSucc = true;
                }
            }
        }

        String userId = serverHttpRequest.getQueryParams().getFirst(PARAMETER_KEY_USER_ID);
        if (!StringUtils.isEmpty(userId)) {
            if (!userId.equals(tokenUserId.toString())) {
                log.error("token和query参数中解析的userId不一致,tokenUserId={},userId={}", tokenUserId, userId);
                return WebUtil.writeAuthFailResponse(exchange, AUTH_FAIL_CODE, AUTH_FAIL_MSG);
            } else {
                authSucc = true;
            }
        }

        if (!authSucc) {
            log.error("缺少userId参数,鉴权失败");
            return WebUtil.writeAuthFailResponse(exchange, AUTH_FAIL_CODE, AUTH_FAIL_MSG);
        }

        return WebUtil.wrapRequestBody(exchange, chain, serverHttpRequest, bodyStr);
    }

    @Override
    public int getOrder() {
        return -10000;
    }
}
