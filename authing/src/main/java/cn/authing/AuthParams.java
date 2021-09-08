package cn.authing;

public class AuthParams {

    // you can set custom callback url after login
    // note all callback urls MUST be registered at Authing console
    private String callbackUrl;

    private String scope = "openid profile email phone address userpool_id";
    private String responseType = "code";

    // can be either authorization_code or refresh_token
    private String grantType = "authorization_code";


    public String getCallbackUrl() {
        return callbackUrl;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }
}
