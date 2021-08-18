package cn.authing.demo;

import cn.authing.AuthParams;
import cn.authing.Authing;
import cn.authing.UserInfo;
import cn.authing.UserPool;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

@RestController
public class HelloWorld {

    @ResponseBody
    @RequestMapping("/home")
    public String hello(HttpServletRequest request, HttpServletResponse response) {
        UserInfo userInfo = Authing.getUserInfo(request, response);
        if (null != userInfo) {
            String email = userInfo.getEmail();
            System.out.println(userInfo);
            return userInfo.getId() + " signed in! Email:" + email;
        } else {
            return "Not signed in";
        }
    }

    @GetMapping("/callback")
    public String loginCallback(HttpServletRequest request, HttpServletResponse response) throws Exception {
        UserInfo userInfo = Authing.onLogin(request, response);
        if (userInfo != null) {
            String curURL = (String)request.getSession().getAttribute(Authing.LAST_VISITED_URL);
            if (curURL == null) {
                curURL = "/home";
            }
            response.sendRedirect(curURL);
            return "";
        }
        return "login failed";
    }

    @ResponseBody
    @RequestMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authing.logout(request, response, "http://app1.mao.com:8080/home");
        return "Logged out";
    }

    @ResponseBody
    @RequestMapping("/getUserPoolListByRoot")
    public Object getUserPoolListByRoot(HttpServletRequest request, @RequestParam String rootUserPoolId, @RequestParam String rootUserPoolSecret) {
        List<UserPool> userPoolListByRoot = Authing.getUserPoolListByRoot(request, rootUserPoolId, rootUserPoolSecret);
        return userPoolListByRoot;
    }
}
