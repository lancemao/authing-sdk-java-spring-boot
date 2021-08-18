package cn.authing.common;

import com.alibaba.fastjson.JSON;

import java.io.Serializable;

/**
 * BasicEntity
 *
 * @author chho
 * @date 2021/08/18
 */
public class BasicEntity implements Serializable {

    @Override
    public String toString() {
        return JSON.toJSONString(this);
    }
}
