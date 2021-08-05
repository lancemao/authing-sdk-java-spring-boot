package cn.authing.internal;

import cn.authing.UserInfo;
import com.auth0.jwt.interfaces.DecodedJWT;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Enumeration;
import java.util.Map;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Util {

    private static final String seed;
    private static final Random rand = new Random();
    private static final int seedLength;

    static {
        String asciiUpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String asciiLowerCase = asciiUpperCase.toLowerCase();
        String digits = "1234567890";
        seed = asciiUpperCase + asciiLowerCase + digits;
        seedLength = seed.length();
    }

    public static String getStringFromStream(InputStream inputStream) {
        BufferedReader in = null;
        StringBuilder res = new StringBuilder();
        try {
            in = new BufferedReader(new InputStreamReader(inputStream));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                res.append(inputLine);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        }
        return res.toString();
    }

    public static String randomString(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0;i < length;++i) {
            sb.append(seed.charAt(rand.nextInt(seedLength)));
        }
        return sb.toString();
    }

    public static String getRequestURLWithParas(HttpServletRequest request) {
        if (null == request) {
            throw new NullPointerException();
        } else {
            String url = request.getRequestURL().toString();
            if (url.lastIndexOf("?") != -1) {
                url = url + "&";
            } else {
                url = url + "?";
            }

            return assemblyParam(request, url);
        }
    }

    private static String assemblyParam(HttpServletRequest request, String url) {
        if (null != request && null != url) {
            Enumeration<?> enum1 = request.getParameterNames();
            String tempName;
            StringBuilder sb = new StringBuilder(url);

            while(enum1.hasMoreElements()) {
                tempName = (String)enum1.nextElement();
                sb.append(tempName);
                sb.append('=');
                sb.append(request.getParameter(tempName));
                sb.append('&');
            }

            url = sb.toString();
            if (url.length() > 1) {
                if ('&' == url.charAt(url.length() - 1)) {
                    url = url.substring(0, url.length() - 1);
                }

                if ('?' == url.charAt(url.length() - 1)) {
                    url = url.substring(0, url.length() - 1);
                }
            }

            return url;
        } else {
            throw new NullPointerException();
        }
    }

    static UserInfo getUserInfo(DecodedJWT jwt) {
        UserInfo userInfo = new UserInfo();

        String userId = jwt.getClaim("sub").asString();
        String birthday = jwt.getClaim("birthday").asString();
        String family_name = jwt.getClaim("family_name").asString();
        String gender = jwt.getClaim("gender").asString();
        String given_name = jwt.getClaim("given_name").asString();
        String locale = jwt.getClaim("locale").asString();
        String middle_name = jwt.getClaim("middle_name").asString();
        String name = jwt.getClaim("name").asString();
        String nickname = jwt.getClaim("nickname").asString();
        String picture = jwt.getClaim("picture").asString();
        String preferred_username = jwt.getClaim("preferred_username").asString();
        String profile = jwt.getClaim("profile").asString();
        String updated_at = jwt.getClaim("updated_at").asString();
        String website = jwt.getClaim("website").asString();
        String zoneinfo = jwt.getClaim("zoneinfo").asString();
        String email = jwt.getClaim("email").asString();
        boolean email_verified = jwt.getClaim("email_verified").asBoolean();
        String phoneNumber = jwt.getClaim("phone_number").asString();
        boolean phone_number_verified = jwt.getClaim("phone_number_verified").asBoolean();
        Map<String, Object> addressMap = jwt.getClaim("address").asMap();
        if (addressMap != null) {
            UserInfo.Address address = new UserInfo.Address();
            address.setCountry((String) addressMap.get("country"));
            address.setPostal_code((String) addressMap.get("postal_code"));
            address.setRegion((String) addressMap.get("region"));
            address.setFormatted((String) addressMap.get("formatted"));
            userInfo.setAddress(address);
        }

        userInfo.setSub(userId);
        userInfo.setBirthday(birthday);
        userInfo.setFamily_name(family_name);
        userInfo.setGender(gender);
        userInfo.setGiven_name(given_name);
        userInfo.setLocale(locale);
        userInfo.setMiddle_name(middle_name);
        userInfo.setName(name);
        userInfo.setNickname(nickname);
        userInfo.setPicture(picture);
        userInfo.setPreferred_username(preferred_username);
        userInfo.setProfile(profile);
        userInfo.setUpdated_at(updated_at);
        userInfo.setWebsite(website);
        userInfo.setZoneinfo(zoneinfo);
        userInfo.setEmail(email);
        userInfo.setEmail_verified(email_verified);
        userInfo.setPhone_number(phoneNumber);
        userInfo.setPhone_number_verified(phone_number_verified);
        return userInfo;
    }

    static void createCookie(HttpServletRequest request, HttpServletResponse response, String key, String value, boolean topDomain) {
        String domain = request.getServerName();
        if (topDomain && !isIp(domain)) {
            domain = domain.replaceAll(".*\\.(?=.*\\.)", "");
        }
        response.addHeader("Set-Cookie", key + "=" + value + "; " +
                "Domain=" + domain + "; Path=/; HttpOnly");
    }

    static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String key, boolean topDomain) {
        String domain = request.getServerName();
        if (topDomain && !isIp(domain)) {
            domain = domain.replaceAll(".*\\.(?=.*\\.)", "");
        }
        response.addHeader("Set-Cookie", key + "=deleted" + "; " +
                "Domain=" + domain + "; Path=/; HttpOnly; Max-Age=-1;");
    }

    static boolean isIp(String name) {
        if (name == null || name.length() == 0) {
            return true;
        }

        // ip v6
        if (name.contains(":")) {
            return true;
        }

        // ip v4
        String numRange = "(\\d{1,2}|(0|1)\\" + "d{2}|2[0-4]\\d|25[0-5])" + "\\."
                + "(\\d{1,2}|(0|1)\\" + "d{2}|2[0-4]\\d|25[0-5])" + "\\."
                + "(\\d{1,2}|(0|1)\\" + "d{2}|2[0-4]\\d|25[0-5])" + "\\."
                + "(\\d{1,2}|(0|1)\\" + "d{2}|2[0-4]\\d|25[0-5])";

        Pattern ip_pattern = Pattern.compile(numRange);
        Matcher match= ip_pattern.matcher(name);
        return match.matches();
    }
}
