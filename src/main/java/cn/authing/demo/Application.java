package cn.authing.demo;

import cn.authing.Authing;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
//        Authing.setAppInfo("611a1918e0aadfa4461cd206", "f9a3f7bae26ff39307dcdf1f7c03ad7a");
//        Authing.setUseDynamicAppInfo(false);
//        Authing.setRootUserPoolId("611a1918b6dd683aee9be801");
//        Authing.setRootUserPoolSecret("e399e89bf7197db16987b16029e6d481");
//        Authing.setHost("https://core.authing.cn");


        Authing.setAppInfo("6125e9d6b95f3b12bf6ad0bd", "f70396e3b292ca1ffbeebcda6ba4568d");
        Authing.setUseDynamicAppInfo(false);
        Authing.setRootUserPoolId("611a1918b6dd683aee9be801");
        Authing.setUserPoolId("611a1918b6dd683aee9be801");
        Authing.setRootUserPoolSecret("e399e89bf7197db16987b16029e6d481");
        Authing.setCallback("https://www.baidu.com");
        Authing.setHost("https://core.authing.cn");



//        Authing.setUserPoolId("59f86b4832eb28071bdd9214");
//        Authing.setAppInfo("60bf6a1343470ba5ac92c404", "8f6f330fb959368013bf88077197feb0");
//        Authing.setUseDynamicAppInfo(true);
//        Authing.setRootUserPoolId("59f86b4832eb28071bdd9214");
//        Authing.setRootUserPoolSecret("98747d9efc5330c64f257190a76467b8");
//        Authing.setHost("http://10.0.0.56:3000");


//        Authing.setUserPoolId("6108dfb786220743825cfad4");
//        Authing.setAppInfo("60bf6a1343470ba5ac92c404", "8f6f330fb959368013bf88077197feb0");
//        Authing.setHost("https://maoism.authing.cn");
//        Authing.setCallback("http://app1.mao.com:8080/callback");
        SpringApplication.run(Application.class, args);
    }
}
