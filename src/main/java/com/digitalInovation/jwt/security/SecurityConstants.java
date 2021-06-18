package com.digitalInovation.jwt.security;

public class SecurityConstants {

    public static final String SECRET = "SecretKeyToGenJWTs";
    public static final long EXPIRATION_TIME = 864_800_800; //10 days
    public static final String TOKEN_PREFIX = "Bearer";
    public static final String MEADER_STRING = "Authorization";
    public static final String SIGN_UP_URL = "/login";
    public static final String STATUS_URL = "/status";
}
