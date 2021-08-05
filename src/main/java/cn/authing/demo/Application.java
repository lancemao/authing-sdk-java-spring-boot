package cn.authing.demo;

import cn.authing.Authing;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        Authing.setUserPoolId("6108dfb786220743825cfad4");
        Authing.setAppInfo("60bf6a1343470ba5ac92c404", "8f6f330fb959368013bf88077197feb0");
        Authing.setHost("https://maoism.authing.cn");
        Authing.setCallback("http://app1.mao.com:8080/callback");
        SpringApplication.run(Application.class, args);
    }
}
