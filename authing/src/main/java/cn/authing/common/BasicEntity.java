package cn.authing.common;

import com.alibaba.fastjson.JSON;

import java.io.Serializable;

public class BasicEntity implements Serializable {

    @Override
    public String toString() {
        return JSON.toJSONString(this);
    }
}
