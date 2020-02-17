package com.cdfive.learning.gateway.filter.sign;

import com.cdfive.learning.gateway.util.WebUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.CollectionUtils;
import org.springframework.util.DigestUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * API签名过滤器
 *
 * @author cdfive
 */
@Slf4j
public class ApiSignGatewayFilter implements GatewayFilter, Ordered {

    private final static Integer SIGN_FAIL_CODE = 30001;

    private final static String SIGN_FAIL_MSG = "签名错误";

    private final static String PARAMETER_KEY_SIGN = "sign";

    private final static String PARAMETER_KEY_OS = "os";

    private final static String PARAMETER_VALUE_OS_ANDROID = "ANDROID";

    private final static String PARAMETER_VALUE_OS_IOS = "IOS";

    private List<String> whiteList;

    public ApiSignGatewayFilter(List<String> whiteList) {
        this.whiteList = whiteList;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest serverHttpRequest = exchange.getRequest();
        log.debug("ip={},path={}", WebUtil.getClientIp(serverHttpRequest), serverHttpRequest.getPath().value());

        if (!CollectionUtils.isEmpty(whiteList)) {
            if (whiteList.contains(exchange.getRequest().getPath().value())) {
                return chain.filter(exchange);
            }
        }

        // 仅APP端才验证签名,通过os参数区分是否是APP端(ANDROID和IOS)
        String os = serverHttpRequest.getQueryParams().getFirst(PARAMETER_KEY_OS);
        if (!PARAMETER_VALUE_OS_ANDROID.equalsIgnoreCase(os) && !PARAMETER_VALUE_OS_IOS.equalsIgnoreCase(os)) {
            return chain.filter(exchange);
        }

        // 获取签名
        String sign = serverHttpRequest.getQueryParams().getFirst(PARAMETER_KEY_SIGN);
        if (StringUtils.isEmpty(sign)) {
            log.error("url参数中解析的签名为空");
            return WebUtil.writeAuthFailResponse(exchange, SIGN_FAIL_CODE, SIGN_FAIL_MSG);
        }

        // 获取查询参数排序,排除sign,拼接字符串
        MultiValueMap<String, String> queryParamMap = serverHttpRequest.getQueryParams();
        List<Map.Entry<String, List<String>>> sortList = WebUtil.sortParameterName(queryParamMap);
        String parameterStr = WebUtil.getParameterContents(sortList, PARAMETER_KEY_SIGN);

        // 获取body参数
        String bodyStr = WebUtil.resolveBodyFromRequest(serverHttpRequest);
        if (bodyStr == null) {
            bodyStr = "";
        }

        // 拼接起来的字符串做md5然后和签名比较
        String md5Before = parameterStr + bodyStr;
        String md5After = DigestUtils.md5DigestAsHex((parameterStr + bodyStr).getBytes());
        if (!md5After.equals(sign)) {
            log.error("签名不一致,参数中解析的签名={},md5加密后的签名={},md5加密前的签名={}", sign, md5After, md5Before);
            return WebUtil.writeAuthFailResponse(exchange, SIGN_FAIL_CODE, SIGN_FAIL_MSG);
        }

        return WebUtil.wrapRequestBody(exchange, chain, serverHttpRequest, bodyStr);
    }

    @Override
    public int getOrder() {
        return -20000;
    }
}
