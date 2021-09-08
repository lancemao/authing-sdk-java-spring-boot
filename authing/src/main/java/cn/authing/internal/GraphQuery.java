package cn.authing.internal;

/**
 * GraphQuery
 *
 */
class GraphQuery {

    public static final String USER_POOL_DOCUMENT_JSON = "{\n" +
            "    \"query\":\"\n" +
            "query userpool {\n" +
            "  userpool {\n" +
            "    id\n" +
            "    name\n" +
            "    domain\n" +
            "    description\n" +
            "    secret\n" +
            "    jwtSecret\n" +
            "    ownerId\n" +
            "    userpoolTypes {\n" +
            "      code\n" +
            "      name\n" +
            "      description\n" +
            "      image\n" +
            "      sdks\n" +
            "    }\n" +
            "    logo\n" +
            "    createdAt\n" +
            "    updatedAt\n" +
            "    emailVerifiedDefault\n" +
            "    sendWelcomeEmail\n" +
            "    registerDisabled\n" +
            "    appSsoEnabled\n" +
            "    showWxQRCodeWhenRegisterDisabled\n" +
            "    allowedOrigins\n" +
            "    tokenExpiresAfter\n" +
            "    isDeleted\n" +
            "    frequentRegisterCheck {\n" +
            "      timeInterval\n" +
            "      limit\n" +
            "      enabled\n" +
            "    }\n" +
            "    loginFailCheck {\n" +
            "      timeInterval\n" +
            "      limit\n" +
            "      enabled\n" +
            "    }\n" +
            "    changePhoneStrategy {\n" +
            "      verifyOldPhone\n" +
            "    }\n" +
            "    changeEmailStrategy {\n" +
            "      verifyOldEmail\n" +
            "    }\n" +
            "    qrcodeLoginStrategy {\n" +
            "      qrcodeExpiresAfter\n" +
            "      returnFullUserInfo\n" +
            "      allowExchangeUserInfoFromBrowser\n" +
            "      ticketExpiresAfter\n" +
            "    }\n" +
            "    app2WxappLoginStrategy {\n" +
            "      ticketExpriresAfter\n" +
            "      ticketExchangeUserInfoNeedSecret\n" +
            "    }\n" +
            "    whitelist {\n" +
            "      phoneEnabled\n" +
            "      emailEnabled\n" +
            "      usernameEnabled\n" +
            "    }\n" +
            "    customSMSProvider {\n" +
            "      enabled\n" +
            "      provider\n" +
            "      config\n" +
            "    }\n" +
            "    packageType\n" +
            "    useCustomUserStore\n" +
            "    loginRequireEmailVerified\n" +
            "    verifyCodeLength\n" +
            "  }\n" +
            "}\n" +
            "\",\n" +
            "    \"variables\":{\n" +
            "        \"userpoolDocument\":\"\n" +
            "query userpool {\n" +
            "  userpool {\n" +
            "    id\n" +
            "    name\n" +
            "    domain\n" +
            "    description\n" +
            "    secret\n" +
            "    jwtSecret\n" +
            "    ownerId\n" +
            "    userpoolTypes {\n" +
            "      code\n" +
            "      name\n" +
            "      description\n" +
            "      image\n" +
            "      sdks\n" +
            "    }\n" +
            "    logo\n" +
            "    createdAt\n" +
            "    updatedAt\n" +
            "    emailVerifiedDefault\n" +
            "    sendWelcomeEmail\n" +
            "    registerDisabled\n" +
            "    appSsoEnabled\n" +
            "    showWxQRCodeWhenRegisterDisabled\n" +
            "    allowedOrigins\n" +
            "    tokenExpiresAfter\n" +
            "    isDeleted\n" +
            "    frequentRegisterCheck {\n" +
            "      timeInterval\n" +
            "      limit\n" +
            "      enabled\n" +
            "    }\n" +
            "    loginFailCheck {\n" +
            "      timeInterval\n" +
            "      limit\n" +
            "      enabled\n" +
            "    }\n" +
            "    changePhoneStrategy {\n" +
            "      verifyOldPhone\n" +
            "    }\n" +
            "    changeEmailStrategy {\n" +
            "      verifyOldEmail\n" +
            "    }\n" +
            "    qrcodeLoginStrategy {\n" +
            "      qrcodeExpiresAfter\n" +
            "      returnFullUserInfo\n" +
            "      allowExchangeUserInfoFromBrowser\n" +
            "      ticketExpiresAfter\n" +
            "    }\n" +
            "    app2WxappLoginStrategy {\n" +
            "      ticketExpriresAfter\n" +
            "      ticketExchangeUserInfoNeedSecret\n" +
            "    }\n" +
            "    whitelist {\n" +
            "      phoneEnabled\n" +
            "      emailEnabled\n" +
            "      usernameEnabled\n" +
            "    }\n" +
            "    customSMSProvider {\n" +
            "      enabled\n" +
            "      provider\n" +
            "      config\n" +
            "    }\n" +
            "    packageType\n" +
            "    useCustomUserStore\n" +
            "    loginRequireEmailVerified\n" +
            "    verifyCodeLength\n" +
            "  }\n" +
            "}\n" +
            "\"\n" +
            "    }\n" +
            "}";
}
