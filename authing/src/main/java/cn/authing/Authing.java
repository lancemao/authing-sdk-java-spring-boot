package cn.authing;

import cn.authing.internal.AuthingImpl;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Authing {

    public static final String LAST_VISITED_URL = "last_visited_url";

    public static void setUserPoolId(String userPoolId) {
        AuthingImpl.setUserPoolId(userPoolId);
    }

    public static void setAppInfo(String appId, String appSecret) {
        AuthingImpl.setAppInfo(appId, appSecret);
    }

    public static void setHost(String host) {
        AuthingImpl.setHost(host);
    }

    public static void setCallback(String callback) {
        AuthingImpl.setCallback(callback);
    }

    public static void setVerifyRemotely(boolean verifyRemotely) {
        AuthingImpl.setVerifyRemotely(verifyRemotely);
    }

    public static void setCookieOnTopDomain(boolean onTopDomain) {
        AuthingImpl.setCookieOnTopDomain(onTopDomain);
    }

    public static void setIncludeIDTokenInCookie(boolean idTokenInCookie) {
        AuthingImpl.setIncludeIDTokenInCookie(idTokenInCookie);
    }

    // 最常用API。该API会校验request里面的凭证，若凭证无效,该接口会重定向到Authing登录界面
    public static UserInfo getUserInfo(HttpServletRequest request, HttpServletResponse response) {
        return getUserInfo(request, response, new AuthParams());
    }

    // 如果gotoLogin为false，服务端不会自动重定向到登录界面。服务端可以返回一个未认证错误，由前台自己处理
    public static UserInfo getUserInfo(HttpServletRequest request, HttpServletResponse response, AuthParams authParams) {
        return AuthingImpl.getUserInfo(request, response, authParams);
    }

    public static UserInfo onLogin(HttpServletRequest request, HttpServletResponse response) {
        return AuthingImpl.onLogin(request, response, new AuthParams());
    }

    public static UserInfo onLogin(HttpServletRequest request, HttpServletResponse response, AuthParams authParams) {
        return AuthingImpl.onLogin(request, response, authParams);
    }

    public static void logout(HttpServletRequest request, HttpServletResponse response, String redirect_uri) {
        AuthingImpl.logout(request, response, redirect_uri);
    }
}
