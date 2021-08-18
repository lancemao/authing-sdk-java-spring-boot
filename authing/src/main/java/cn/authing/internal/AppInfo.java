package cn.authing.internal;

import cn.authing.common.BasicEntity;

import java.util.List;

class AppInfo extends BasicEntity {

    private String id;
    private String secret;
    private List<String> redirectUris;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }
}
