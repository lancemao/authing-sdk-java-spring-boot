package cn.authing;

import cn.authing.common.BasicEntity;

import java.util.Map;

/**
 * CooperatorInfo
 *
 */
public class CooperatorInfo extends BasicEntity {

    private UserInfo user;

    private Map<String, Object> policies;

    public UserInfo getUser() {
        return user;
    }

    public void setUser(UserInfo user) {
        this.user = user;
    }

    public Map<String, Object> getPolicies() {
        return policies;
    }

    public void setPolicies(Map<String, Object> policies) {
        this.policies = policies;
    }
}
