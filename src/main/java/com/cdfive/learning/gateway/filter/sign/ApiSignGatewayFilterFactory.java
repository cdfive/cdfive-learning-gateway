package com.cdfive.learning.gateway.filter.sign;

import lombok.Getter;
import lombok.Setter;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

/**
 * API签名过滤器工厂
 *
 * @author cdfive
 */
@Component
public class ApiSignGatewayFilterFactory extends AbstractGatewayFilterFactory<ApiSignGatewayFilterFactory.Config> {

    public ApiSignGatewayFilterFactory() {
        super(ApiSignGatewayFilterFactory.Config.class);
    }

    @Override
    public GatewayFilter apply(ApiSignGatewayFilterFactory.Config config) {
        return new ApiSignGatewayFilter(config.whiteList);
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("whiteList");
    }

    @Getter
    @Setter
    public static class Config {
        private List<String> whiteList;
    }
}
