package cn.authing;

import cn.authing.common.BasicEntity;

/**
 * UserPoolDetail
 */
public class UserPoolDetail extends BasicEntity {

    private UserPool userPool;

    public UserPool getUserPool() {
        return userPool;
    }

    public void setUserPool(UserPool userPool) {
        this.userPool = userPool;
    }
}
