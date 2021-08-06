# Authing Spring Boot Java SDK

超越同类产品的关键特性：

* 支持凭证**本地校验**和**远程校验**两种模式
* 支持同域（可跨技术栈） App 的**单点登录，单点登出**
* 支持登录成功后自动跳转到用户**当前所在地址**，而不是强迫用户跳转到首页
* 提供**业务**友好的API，隐藏技术细节
* 支持 **JDK 1.7** 及以上

下面简单介绍关键特性，更详细的信息请移步至 [Authinng 开发者社区](https://docs.authing.cn/v2/quickstarts/webApp/javaSpringBoot.html)

<br>

## 凭证本地校验和远程校验两种模式

几乎所有主流身份云产品都基于 OpenID Connect，当用户认证成功后，认证服务器会返回 access token 和 id token。id token 里面包含了用户信息，同时包含了签名数据，可以确保不被被篡改。

在**本地校验模式**下，客户端使用服务器提供的密钥对其进行校验，可以极大提高性能，从而提高最终用户体验。

在**远程校验模式**下，客户端总是将凭证发送给认证服务器进行校验，可以确保凭证实时有效。这种模式的性能会明显低于**本地校验模式**，但可以解决如下场景：用户修改了密码，手动召回了凭证，保留了会话的终端仍然可以继续访问业务系统。

<br>

## 同域（可跨技术栈） App 的单点登录，单点登出

大部分身份云产品都支持单点登录，但极少能正确处理单点登出。假设某公司有A，B两个应用，地址分别为：a.example.cn，b.example.cn。如果用户在 A 应用里面登出，对于同一个企业的应用来说，在绝大多数场景下，B 应用也应该登出。由于一般的 IDaaS 都使用了会话，那 A，B 两个应用是两个独立的会话，登出 A 并不会（也不应该）清理 B 的会话。好消息是，在不需要应用发各种通知或者回调的前提下，我们创造性的解决了这个问题，应用只需要简单调用登出接口就可以了。

<br>

## 支持登录成功后自动跳转到用户当前地址，而不是强迫用户跳转到首页

OAuth 2.0 协议要求，授权回调地址**必须**提前和授权服务器协商。于是，我们就必须在身份云管理控制台去设置一个合法的回调地址。然后问题就来了，假设用户通过多次点击来到了一个地址层级比较深的位置，如果等会儿会话超时（比如第二天来上班），那么用户会被强迫跳转到身份云管理控制台设置的回调地址，一般是应用首页，他必须重新多次点击才能回到上次访问的地址。

实际上，大部分的用户每天会打开很多浏览器 tab，这些 tab 对应了他们的日常工作，他们下班的时候并不会关闭这些 tab，他们希望第二天来上班的时候，只需要重新登录一次，就可以无缝继续昨天的工作。

<br>

## 提供业务友好的API，隐藏技术细节

* 应用开发者不需要了解 OAuth 2.0 或者 OpenID Connect 原理，就可以快速实现认证功能。
* 我们直接返回了 UserInfo Java 对象，而不是 RAW JSON。

<br>

## 支持 JDK 1.7 及以上

是的，还有不少应用只支持 JDK 1.7

# API 使用说明

## 初始化

如果你是从 Authing 管理控制台具体某应用下面通过点击"接入教程"下载的 Java Spring Boot Demo，我们已经自动为你填充了初始化代码，可以直接运行。

如果你是手动创建的 Spring 工程，首先需要配置 pom 依赖

```xml
<dependency>
    <groupId>cn.authing</groupId>
    <artifactId>java-sdk-spring-boot</artifactId>
    <version>1.0.0</version>
</dependency>
```

确保在 Authing 控制台设置了回调地址

然后在应用启动的时候，调用如下接口进行初始化。

```java
Authing.setUserPoolId("your user pool id");
Authing.setAppInfo("your appid", "your app secret");
Authing.setHost("your host");
Authing.setCallback("your login callback");
```

## 登录

在需要获取用户信息的地方按如下方式调用 Authing.getUserInfo，若用户没有登录或者登录凭证过期，该函数会自动跳转到登录界面。
我们没有封装 filter，应用可以根据需要自行封装。

```java
@ResponseBody
@RequestMapping("/home")
public String hello(HttpServletRequest request, HttpServletResponse response) {
    UserInfo userInfo = Authing.getUserInfo(request, response);
    if (null != userInfo) {
        String email = userInfo.getEmail();
        return userInfo.getUid() + " signed in! Email:" + email;
    } else {
        return "Not signed in";
    }
}
```

登录回调，支持跳转到登录前位置：

```java
@GetMapping("/callback")
public String loginCallback(HttpServletRequest request, HttpServletResponse response) throws Exception {
    UserInfo userInfo = Authing.onLogin(request, response);
    if (userInfo != null) {
        String curURL = (String)request.getSession().getAttribute(Authing.LAST_VISITED_URL);
        response.sendRedirect(curURL);
        return "";
    }
    return "login failed";
}
```

## 登出：

```java
@ResponseBody
@RequestMapping("/logout")
public String logout(HttpServletRequest request, HttpServletResponse response) {
    Authing.logout(request, response, "http://localhost:8080/home");
    return "Logged out";
}
```

## 其他 API：

### 设置本地校验还是远程校验
```java
Authing.setVerifyRemotely(boolean verifyRemotely)
```

本地校验性能更好。远程校验更安全。默认为 **false**，即本地校验。

<br>

### 设置 Cookie 是否被 Set 在顶级域名下

```java
Authing.setCookieOnTopDomain(boolean onTopDomain)
```

在同一企业内部的 App 推荐设置在企业的顶级域名下。默认为 **true**。

<br>

### 设置 Cookie 是否包含身份凭证（ID Token）

```java
Authing.setIncludeIDTokenInCookie(boolean idTokenInCookie)
```

当为 true 时，认证通过后会将 ID Token 返回给端侧，存到 Cookie 里面。在同一企业内部跨 App 场景下，可以达到最好体验和性能。
默认为 **true**。
