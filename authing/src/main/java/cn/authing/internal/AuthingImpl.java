package cn.authing.internal;

import cn.authing.AuthParams;
import cn.authing.Authing;
import cn.authing.UserInfo;
import cn.authing.UserPool;
import cn.authing.common.AuthingResult;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class AuthingImpl {

    private static final Logger logger = LoggerFactory.getLogger(AuthingImpl.class);

    private static final String PATH_SIGN_IN = "/oidc/auth?client_id=";
    private static final String PATH_GET_AK = "/oidc/token";
    private static final String PATH_ME = "/oidc/me?access_token=";
    private static final String PATH_USERS_ME = "/api/v2/users/me";
    private static final String PATH_JWKS = "/oidc/.well-known/jwks.json";
    private static final String PATH_GET_APP_INFO = "/api/v2/applications/getAppInfo/default";
    private static final String PATH_GET_USER_POOL_LIST = "/api/v2/userpools/getUserPoolList";

    private static final String APP_SESSION_ID = "authing_app_session_id";
    private static final String APP_ID_TOKEN = "authing_id_token";

    private static final String DOMAIN_SUFFIX = ".";

    private static final int CONNECTION_TIMEOUT = 10000;

    private static long sCacheValidDuration = 10 * 60 * 60 * 1000;

    static String sUserPoolId;

    static String sAppId;
    static String sAppSecret;

    // endpoint host
    // also used to retrieve jwks
    static String sHost;

    // default callback
    static String sCallbackUrl;

    // parsed from sHost+/.well-known/jwks.json
    static Jwk sJWK;

    // if true, always verify token remotely. this is more secure but less performant
    static boolean sVerifyRemotely;

    // if true, apps in the same domain can share cookie
    // although each app logs in on their own, user won`t feel it
    // plus, when one app logs out, all app logs out as well
    static boolean sSetCookieOnTopDomain = true;

    static boolean sIncludeIDTokenInCookie = true;

    static boolean sUseDynamicAppInfo = false;

    static String sRootUserPoolId;

    static String sRootUserPoolSecret;

    static final Map<String, AppInfo> sDomainAppInfoRegistry = new ConcurrentHashMap<>();

    private static final Map<String, AuthInfo> sCache = new ConcurrentHashMap<>();
    private static final CleanCacheTask cleanCacheTask = new CleanCacheTask();
    private static final Timer timer = new Timer();

    static {
        timer.scheduleAtFixedRate(cleanCacheTask, 0, TimeUnit.HOURS.toMillis(1));
    }

    public static void setUserPoolId(String userPoolId) {
        sUserPoolId = userPoolId;
    }

    public static void setAppInfo(String appId, String appSecret) {
        sAppId = appId;
        sAppSecret = appSecret;
    }

    public static void setHost(String host) {
        sHost = host;
        if (sHost != null) {
            sJWK = Jwk.create(sHost + PATH_JWKS);
        }
    }

    public static void setCallback(String callback) {
        sCallbackUrl = callback;
    }

    public static void setVerifyRemotely(boolean verifyRemotely) {
        AuthingImpl.sVerifyRemotely = verifyRemotely;
    }

    public static void setCookieOnTopDomain(boolean onTopDomain) {
        AuthingImpl.sSetCookieOnTopDomain = onTopDomain;
    }

    public static void setIncludeIDTokenInCookie(boolean idTokenInCookie) {
        AuthingImpl.sIncludeIDTokenInCookie = idTokenInCookie;
    }

    public static void setUseDynamicAppInfo(boolean useDynamicAppInfo) {
        sUseDynamicAppInfo = useDynamicAppInfo;
    }

    public static void setRootUserPoolId(String rootUserPoolId) {
        sRootUserPoolId = rootUserPoolId;
    }

    public static void setRootUserPoolSecret(String rootUserPoolSecret) {
        sRootUserPoolSecret = rootUserPoolSecret;
    }

    public static UserInfo getUserInfo(HttpServletRequest request, HttpServletResponse response, AuthParams authParams) {

        if (getAppId(request) == null || getAppSecret(request) == null) {
            logger.error("app info not set. Please call Authing.setAppInfo(appId, appSecret) during app startup " +
                    "when useDynamicAppInfo is false. Please call Authing.setRootUserPoolId(String rootUserPoolId) " +
                    "and Authing.setRootUserPoolSecret(String rootUserPoolSecret) during app startup " +
                    "when useDynamicAppInfo is true");
            return null;
        }

        if (sHost == null) {
            logger.error("app host not set. Please call Authing.setHost(host) during app startup. " +
                    "Note this host is your app specific, e.g. https://myapp.authing.cn");
            return null;
        }

        if (getCallbackUrl(request) == null) {
            logger.error("callback url not set. Please call Authing.setCallback(callbackUrl) during app startup. " +
                    "as per OAuth 2.0 specification, callback has to be negotiated during registration");
            return null;
        }

        try {
            UserInfo userInfo = verify(request);
            if (userInfo != null) {
                return userInfo;
            }

            String authorization = request.getHeader("Authorization");
            if (authorization == null) {
                authorization = request.getHeader("authorization");
            }
            if (authorization != null) {
                userInfo = getUserInfoByToken(authorization);
            }

            if (userInfo == null) {
                gotoSignIn(request, response, authParams);
            }
            return userInfo;
        } catch (Exception e) {
            logger.error("getUserInfo exception", e);
            return null;
        }
    }

    private static void gotoSignIn(HttpServletRequest request, HttpServletResponse response, AuthParams authParams) throws Exception {
        if (authParams == null || !authParams.isGotoLogin()) {
            return;
        }

        // save current url to session
        String cur = Util.getRequestURLWithParas(request);
        request.getSession(true).setAttribute(Authing.LAST_VISITED_URL, cur);

        String callbackUrl = authParams.getCallbackUrl();
        if (callbackUrl == null) {
            callbackUrl = getCallbackUrl(request);
        }
        String url = sHost + PATH_SIGN_IN + getAppId(request) +
                "&scope=" + authParams.getScope() +
                "&state=" + Util.randomString(12) +
                "&nonce=" + Util.randomString(12) +
                "&response_type=" + authParams.getResponseType() +
                "&redirect_uri=" + URLEncoder.encode(callbackUrl, "utf-8");
        response.sendRedirect(url);
    }

    public static UserInfo onLogin(HttpServletRequest request, HttpServletResponse response, AuthParams authParams) {
        String code = request.getParameter("code");
        if (code == null || code.length() == 0) {
            logger.error("Auth failed. Code is empty");
            return null;
        }

        try {
            URL obj = new URL(sHost + PATH_GET_AK);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
            con.setConnectTimeout(CONNECTION_TIMEOUT);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            con.setDoOutput(true);
            OutputStream os = con.getOutputStream();
            String callbackUrl = authParams.getCallbackUrl();
            if (callbackUrl == null) {
                callbackUrl = getCallbackUrl(request);
            }
            String body = "client_id=" + getAppId(request)
                    + "&client_secret=" + getAppSecret(request)
                    + "&grant_type=" + authParams.getGrantType()
                    + "&code=" + code
                    + "&redirect_uri=" + callbackUrl;
            os.write(body.getBytes());
            os.flush();
            os.close();

            int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) { //success
                String res = Util.getStringFromStream(con.getInputStream());
                AuthInfo authInfo = JSON.parseObject(res, AuthInfo.class);
                if (authInfo == null || authInfo.getId_token() == null || authInfo.getAccess_token() == null) {
                    logger.error("Auth failed. AK or ID Token is empty");
                    return null;
                }

                UserInfo userInfo;
                String appSessionID = getAppSessionID(request);
                if (sVerifyRemotely) {
                    userInfo = verifyTokenRemotely(authInfo.getAccess_token());
                    if (userInfo != null) {
                        authInfo.setLastValidTime(System.currentTimeMillis());
                        sCache.put(appSessionID, authInfo);
                    }
                } else {
                    userInfo = verify(appSessionID, authInfo.getId_token(), getAppSecret(request));
                }

                Util.createCookie(request, response, APP_SESSION_ID, appSessionID, sSetCookieOnTopDomain);
                if (sIncludeIDTokenInCookie) {
                    Util.createCookie(request, response, APP_ID_TOKEN, authInfo.getId_token(), sSetCookieOnTopDomain);
                }

                if (userInfo == null) {
                    logger.error("Auth failed. verify token failed");
                } else {
                    userInfo.setAccessToken(authInfo.getAccess_token());
                }
                return userInfo;
            } else {
                String res = Util.getStringFromStream(con.getErrorStream());
                logger.error("get access token failed. Status code:" + responseCode + " Error:" + res);
                return null;
            }
        } catch (Exception e) {
            logger.error("get access token failed:", e);
        }
        return null;
    }

    private static String getAppId(HttpServletRequest request) {
        if (sUseDynamicAppInfo) {
            AppInfo appInfo = getDynamicAppInfoByRequestDomain(request);
            if (appInfo == null) {
                return null;
            }
            return appInfo.getId();
        }
        return sAppId;
    }

    private static String getAppSecret(HttpServletRequest request) {
        if (sUseDynamicAppInfo) {
            AppInfo appInfo = getDynamicAppInfoByRequestDomain(request);
            if (appInfo == null) {
                return null;
            }
            return appInfo.getSecret();
        }
        return sAppSecret;
    }

    private static String getCallbackUrl(HttpServletRequest request) {
        if (sUseDynamicAppInfo) {
            AppInfo appInfo = getDynamicAppInfoByRequestDomain(request);
            if (appInfo == null) {
                return null;
            }
            if (appInfo.getRedirectUris() ==  null || appInfo.getRedirectUris().size() == 0) {
                return null;
            }
            return appInfo.getRedirectUris().get(0);
        }
        return sCallbackUrl;
    }

    private static String getAuthorization(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization == null) {
            authorization = request.getHeader("authorization");
        }
        return authorization;
    }

    private static AppInfo getDynamicAppInfoByRequestDomain(HttpServletRequest request) {
        if (sRootUserPoolId == null || sRootUserPoolSecret == null) {
            logger.error("Get dynamic app info fail, rootUserPoolId is null or rootUserPoolSecret is null");
            return null;
        }
        // 截取域名前缀
        StringBuffer url = request.getRequestURL();
        String host = url.substring(request.getScheme().length() + 3, (url.length() - request.getRequestURI().length()));
        String domain;
        if (host.contains(DOMAIN_SUFFIX)) {
            domain = host.substring(0, host.indexOf(DOMAIN_SUFFIX));
        } else {
            logger.error("Get dynamic app info fail, invalid host named [{}]", host);
            return null;
        }

        AppInfo appInfo = sDomainAppInfoRegistry.get(domain);
        if (appInfo != null) {
            return appInfo;
        }

        try {
            URL obj = new URL(sHost + PATH_GET_APP_INFO);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json;charset=UTF-8");
            con.setRequestProperty("Authorization", getAuthorization(request));
            con.setConnectTimeout(CONNECTION_TIMEOUT);
            con.setDoOutput(true);
            DataOutputStream os = new DataOutputStream(con.getOutputStream());
            Properties params = new Properties();
            params.put("rootUserPoolId", sRootUserPoolId);
            params.put("rootUserPoolSecret", sRootUserPoolSecret);
            params.put("domain", domain);
            os.write(JSON.toJSONString(params).getBytes());
            os.flush();
            os.close();

            int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK || HttpURLConnection.HTTP_CREATED == responseCode) {
                String resStr = Util.getStringFromStream(con.getInputStream());
                AuthingResult<AppInfo> res = JSON.parseObject(resStr, new TypeReference<AuthingResult<AppInfo>>() {
                });
                if (AuthingResult.OK == res.getCode()) {
                    appInfo = res.getData();
                    if (appInfo == null || appInfo.getId() == null || appInfo.getSecret() == null) {
                        logger.error("Get app info failed. App id or app secret is empty");
                        return null;
                    }

                    sDomainAppInfoRegistry.put(domain, appInfo);
                    return appInfo;
                } else {
                    logger.error("Get app info failed. Authing result code:" + res.getCode()
                            + ", Authing result message:" + res.getMessage());
                }
            } else {
                String res = Util.getStringFromStream(con.getErrorStream());
                logger.error("Get app info failed. Status code:" + responseCode + ", Error:" + res);
            }
        } catch (Exception e) {
            logger.error("Get app info failed. ", e);
        }
        return null;
    }

    private static UserInfo verify(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        String appSessionID = getAppSessionIDFromCookie(cookies);
        if (sIncludeIDTokenInCookie) {
            String idToken = getIDTokenFromCookie(cookies);
            if (sVerifyRemotely) {
                return verifyTokenRemotely(idToken);
            } else {
                return verify(appSessionID, idToken, getAppSecret(request));
            }
        } else {
            if (sVerifyRemotely) {
                if (appSessionID != null) {
                    AuthInfo authInfo = sCache.get(appSessionID);
                    if (authInfo != null) {
                        return verifyTokenRemotely(authInfo.getAccess_token());
                    } else {
                        return null;
                    }
                } else {
                    return null;
                }
            } else {
                return verify(appSessionID, null, getAppSecret(request));
            }
        }
    }

    private static UserInfo verify(String key, String idToken, String appSecret) {
        if (key == null || key.length() == 0) {
            return null;
        }

        AuthInfo cache = sCache.get(key);
        if (cache != null) {
            long now = System.currentTimeMillis();
            if (now - cache.getLastValidTime() < sCacheValidDuration) {
                cache.setLastValidTime(now);
                return cache.getUserInfo();
            } else {
                sCache.remove(key);
                return null;
            }
        } else {
            if (idToken != null && idToken.length() > 0) {
                UserInfo userInfo = verifyIdToken(idToken, appSecret);
                if (userInfo != null) {
                    AuthInfo authInfo = new AuthInfo();
                    authInfo.setUserInfo(userInfo);
                    authInfo.setLastValidTime(System.currentTimeMillis());
                    sCache.put(key, authInfo);
                    return userInfo;
                }
            }
        }
        return null;
    }

    private static UserInfo verifyTokenRemotely(String accessToken) {
        if (accessToken == null || accessToken.length() == 0) {
            return null;
        }

        try {
            URL obj = new URL(sHost + PATH_ME + accessToken);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
            con.setConnectTimeout(CONNECTION_TIMEOUT);
            int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) { //success
                String res = Util.getStringFromStream(con.getInputStream());
                UserInfo userInfo = JSON.parseObject(res, UserInfo.class);
                if (userInfo == null) {
                    logger.error("Get user info failed");
                    return null;
                }
                return userInfo;
            } else {
                String res = Util.getStringFromStream(con.getErrorStream());
                logger.error("verify access token failed. Status code:" + responseCode + " Error:" + res);
                return null;
            }
        } catch (Exception e) {
            logger.error("verify access token failed:", e);
        }
        return null;
    }

    private static UserInfo getUserInfoByToken(String token) {
        if (token == null || token.length() == 0 || sUserPoolId == null) {
            return null;
        }

        try {
            URL obj = new URL(sHost + PATH_USERS_ME);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
            con.setRequestProperty("x-authing-userpool-id", sUserPoolId);
            con.setRequestProperty("Authorization", token);
            con.setConnectTimeout(CONNECTION_TIMEOUT);
            int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) { //success
                String res = Util.getStringFromStream(con.getInputStream());
                GetUserByTokenResponse response = JSON.parseObject(res, GetUserByTokenResponse.class);
                if (response == null) {
                    logger.error("Get user info failed");
                    return null;
                }
                return response.getData();
            } else {
                String res = Util.getStringFromStream(con.getErrorStream());
                logger.error("verify access token failed. Status code:" + responseCode + " Error:" + res);
                return null;
            }
        } catch (Exception e) {
            logger.error("verify access token failed:", e);
        }
        return null;
    }

    private static UserInfo verifyIdToken(String idToken, String appSecret) {
        try {
            DecodedJWT jwt = verifyToken(idToken, appSecret);
            if (jwt == null) {
                return null;
            }

            if (jwt.getExpiresAt().before(Calendar.getInstance().getTime())) {
                throw new RuntimeException("Expired token!");
            }

            sCacheValidDuration = jwt.getExpiresAt().getTime() - Calendar.getInstance().getTimeInMillis();

            return Util.getUserInfo(jwt);
        } catch (SignatureVerificationException e) {
            logger.error("jwt verification failed", e);
        } catch (Exception e) {
            logger.error("jwt verification exception", e);
        }
        return null;
    }

    private static DecodedJWT verifyToken(String idToken, String appSecret) {
        DecodedJWT jwt = Jwk.verifyToken(idToken, sJWK, appSecret);
        if (jwt == null) {
            // key might be rotated. try again
            sJWK = Jwk.create(sHost + PATH_JWKS);
            jwt = Jwk.verifyToken(idToken, sJWK, appSecret);
        }
        return jwt;
    }

    public static void logout(HttpServletRequest request, HttpServletResponse response, String redirect_uri) {
        try {
            Cookie[] cookies = request.getCookies();
            String appSessionID = getAppSessionIDFromCookie(cookies);
            if (appSessionID != null && appSessionID.length() > 0) {
                sCache.remove(appSessionID);
            }

            Util.deleteCookie(request, response, APP_SESSION_ID, sSetCookieOnTopDomain);
            Util.deleteCookie(request, response, APP_ID_TOKEN, sSetCookieOnTopDomain);

            String url = sHost + "/login/profile/logout";
            if (redirect_uri != null) {
                url += "?redirect_uri=" + redirect_uri;
            }
            response.sendRedirect(url);
        } catch (Exception e) {
            logger.error("logout failed", e);
        }
    }

    private static String getAppSessionID(HttpServletRequest request) {
        String sessionID = getAppSessionIDFromCookie(request.getCookies());
        if (sessionID != null && sessionID.length() > 0) {
            return sessionID;
        } else {
            return Util.randomString(16);
        }
    }

    private static String getAppSessionIDFromCookie(Cookie[] cookies) {
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (APP_SESSION_ID.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private static String getIDTokenFromCookie(Cookie[] cookies) {
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (APP_ID_TOKEN.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    public static List<UserPool> getUserPoolListByRoot(HttpServletRequest request, String rootUserPoolId, String rootUserPoolSecret) {
        try {
            URL obj = new URL(sHost + PATH_GET_USER_POOL_LIST);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json;charset=UTF-8");
            con.setRequestProperty("Authorization", getAuthorization(request));
            con.setConnectTimeout(CONNECTION_TIMEOUT);
            con.setDoOutput(true);
            DataOutputStream os = new DataOutputStream(con.getOutputStream());
            Properties params = new Properties();
            params.put("rootUserPoolId", rootUserPoolId);
            params.put("rootUserPoolSecret", rootUserPoolSecret);
            os.write(JSON.toJSONString(params).getBytes());
            os.flush();
            os.close();

            int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK || HttpURLConnection.HTTP_CREATED == responseCode) {
                String resStr = Util.getStringFromStream(con.getInputStream());
                AuthingResult<List<UserPool>> res = JSON.parseObject(resStr, new TypeReference<AuthingResult<List<UserPool>>>() {
                });
                if (AuthingResult.OK == res.getCode()) {
                    return res.getData();
                } else {
                    logger.error("Get user pool list by root info failed. Authing result code:" + res.getCode()
                            + ", Authing result message:" + res.getMessage());
                }
            } else {
                String res = Util.getStringFromStream(con.getErrorStream());
                logger.error("Get app info failed. Status code:" + responseCode + ", Error:" + res);
            }
        } catch (Exception e) {
            logger.error("Get app info failed. ", e);
        }
        return null;
    }

    private static class CleanCacheTask extends TimerTask {
        @Override
        public void run() {
            Date date = new Date();
            Calendar cal = Calendar.getInstance();
            cal.setTime(date);
            if (cal.get(Calendar.HOUR_OF_DAY) == 3) {
                StatsUtil.trace();
            }

            try {
                long now = System.currentTimeMillis();
                for (Map.Entry<String, AuthInfo> entry : sCache.entrySet()) {
                    AuthInfo cache = entry.getValue();
                    if (now - cache.getLastValidTime() > sCacheValidDuration) {
                        sCache.remove(entry.getKey());
                    }
                }
            } catch (Exception ex) {
                logger.error("Error when clean cache " + ex.getMessage());
            }
        }
    }
}
