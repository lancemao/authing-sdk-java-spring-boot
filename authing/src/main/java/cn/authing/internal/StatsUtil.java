package cn.authing.internal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import java.net.HttpURLConnection;
import java.net.URL;

public class StatsUtil {

    private static final String URL_SDK = "https://developer-beta.authing.cn/stats/sdk-trace";
    private static final String SDK_VERSION = "1.0.0";
    private static final int AUDIT_TIMEOUT = 3000;

    private static final Logger logger = LoggerFactory.getLogger(StatsUtil.class);

    public static void trace() {
        if (AuthingImpl.sUseDynamicAppInfo) {
            for (AppInfo appInfo : AuthingImpl.sDomainAppInfoRegistry.values()) {
                doTrace(appInfo.getId(), appInfo.getSecret());
            }
        } else {
            doTrace(AuthingImpl.sAppId, AuthingImpl.sAppSecret);
        }
    }

    private static void doTrace(String appId, String appSecret) {
        try {
            URL obj = new URL(URL_SDK + "?appid=" + appId
                    + "&appSecret=" + appSecret
                    + "&sdk=java-spring-boot&version=" + SDK_VERSION);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
            con.setConnectTimeout(AUDIT_TIMEOUT);
            int responseCode = con.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) { //success
                logger.info("sdk trace failed:" + responseCode);
            }
        } catch (Exception e) {
            logger.error("sdk trace failed:", e);
        }
    }
}
