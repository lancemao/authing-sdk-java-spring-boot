package cn.authing;

import cn.authing.internal.AuthingImpl;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

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

    public static void setUseDynamicAppInfo(boolean useDynamicAppInfo) {
        AuthingImpl.setUseDynamicAppInfo(useDynamicAppInfo);
    }

    public static void setRootUserPoolId(String rootUserPoolId) {
        AuthingImpl.setRootUserPoolId(rootUserPoolId);
    }

    public static void setRootUserPoolSecret(String rootUserPoolSecret) {
        AuthingImpl.setRootUserPoolSecret(rootUserPoolSecret);
    }

    // 最常用 API。该 API 会校验 request 里面的凭证，若凭证无效,该接口会返回 null
    public static UserInfo getUserInfo(HttpServletRequest request, HttpServletResponse response) {
        return getUserInfo(request, response, new AuthParams());
    }

    public static UserInfo getUserInfo(HttpServletRequest request, HttpServletResponse response, AuthParams authParams) {
        return AuthingImpl.getUserInfo(request, response, authParams);
    }

    public static String buildSignInUrl(HttpServletRequest request) {
        return buildSignInUrl(request, new AuthParams());
    }

    public static String buildSignInUrl(HttpServletRequest request, AuthParams authParams) {
        return AuthingImpl.buildSignInUrl(request, authParams);
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

    public static List<UserPool> getUserPoolListByRoot(HttpServletRequest request, String rootUserPoolId, String rootUserPoolSecret) {
        return AuthingImpl.getUserPoolListByRoot(request, rootUserPoolId, rootUserPoolSecret);
    }

    public static Boolean isUserPoolAdministrator(HttpServletRequest request, String userId) {
        return AuthingImpl.isUserPoolAdministrator(request, userId);
    }

}
