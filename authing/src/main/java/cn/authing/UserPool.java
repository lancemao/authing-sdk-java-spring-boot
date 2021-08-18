package cn.authing;

import cn.authing.common.BasicEntity;

/**
 * UserPool
 */
public class UserPool extends BasicEntity {

    private String id;
    private String secret;

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
}
