package com.hardont.test;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.crypto.digest.DigestAlgorithm;
import cn.hutool.crypto.digest.Digester;
import cn.hutool.http.HttpResponse;
import cn.hutool.http.HttpUtil;
import cn.hutool.json.JSON;
import cn.hutool.json.JSONUtil;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author hardont
 * @version 1.0
 * @email 446939455@qq.com
 * @date 2021/2/4 16:26
 */
public class TeslaOauthDemo {
    static final String IDENTITY = "email";
    static final String CREDENTIAL = "password";

    public static void main(String[] args) {
        System.out.println("----------生成随机参数-----------");

        String codeVerifier = RandomUtil.randomString(86);
        String codeChallenge = toCodeChallenge(codeVerifier);
        String state = RandomUtil.randomString(20);

        System.out.println("codeVerifier: " + codeVerifier);
        System.out.println("codeChallenge: " + codeChallenge);
        System.out.println("state: " + state);

        //step1 get hidden form
        System.out.println("----------获取表格参数-----------");
        String url = "https://auth.tesla.com/oauth2/v3/authorize?client_id=ownerapi&code_challenge=" + codeChallenge +
                "&code_challenge_method=S256&redirect_uri=https://auth.tesla.com/void/callback&response_type=code&scope=openid%20email%20offline_access&state=" + state;
        HttpResponse execute = HttpUtil.createGet(url).header("User-Agent", "Faraday v1.3.0").execute();
        Map<String, Object> form = parseForm(execute.body());
        System.out.println("----------获取cookie-----------");
        String cookie = getCookie(execute);
        System.out.println("----------step1 cookie:" + cookie + "-----------");

        //step2 post hidden form data
        String step2Url = "https://auth.tesla.com/oauth2/v3/authorize?client_id=ownerapi&code_challenge=" + codeChallenge +
                "&code_challenge_method=S256&redirect_uri=https://auth.tesla.com/void/callback&response_type=code&scope=openid%20email%20offline_access&state=" + state;
        HashMap<String, String> step2Headers = new HashMap<>();
        step2Headers.put("Cookie", cookie);
        step2Headers.put("User-Agent", "Faraday v1.3.0");
        HttpUtil.createPost(step2Url).form(form).addHeaders(step2Headers).setFollowRedirects(false).execute();


        //step3 get hidden form again(uri add login_hint)
        String step3Url = "https://auth.tesla.cn/oauth2/v3/authorize?client_id=ownerapi&code_challenge=" + codeChallenge +
                "&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fauth.tesla.com%2Fvoid%2Fcallback&response_type=code&scope=openid+email+offline_access&state=" + state + "&login_hint=" + IDENTITY;
        HttpResponse step3Execute = HttpUtil.createGet(step3Url).header("User-Agent", "Faraday v1.3.0").setFollowRedirects(false).execute();
        String step3Cookie = getCookie(step3Execute);
        Map<String, Object> step3Form = parseForm(step3Execute.body());
        System.out.println("----------step3 cookie:" + step3Cookie + "-----------");
        System.out.println("----------step3 form:" + step3Form + "-----------");

        //step4 post hidden form again(uri add login_hint) it can get the code
        HashMap<String, String> step4Headers = new HashMap<>();
        step4Headers.put("User-Agent", "Faraday v1.3.0");
        step4Headers.put("Cookie", step3Cookie);
        String step4Url = "https://auth.tesla.cn/oauth2/v3/authorize?client_id=ownerapi&code_challenge=" + codeChallenge +
                "&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fauth.tesla.com%2Fvoid%2Fcallback&response_type=code&scope=openid+email+offline_access&state=" + state + "&login_hint=" + IDENTITY;
        HttpResponse step4Execute = HttpUtil.createPost(step4Url).form(step3Form).addHeaders(step4Headers).setFollowRedirects(false).execute();

        List<String> location = step4Execute.headers().get("Location");
        String code = location.get(0).split("\\?")[1].split("&")[0].split("=")[1];

        //step5 use the code to get access token
        HashMap<String, String> step5Headers = new HashMap<>();
        step5Headers.put("User-Agent", "Faraday v1.3.0");
        Map<String, Object> step5Form = new HashMap<>();
        step5Form.put("grant_type", "authorization_code");
        step5Form.put("client_id", "ownerapi");
        step5Form.put("code", code);
        step5Form.put("code_verifier", codeVerifier);
        step5Form.put("redirect_uri", "https://auth.tesla.com/void/callback");

        HttpResponse step5Execute = HttpUtil.createPost("https://auth.tesla.cn/oauth2/v3/token").addHeaders(step5Headers).form(step5Form).execute();
        String body = step5Execute.body();
        JSON step5Json = JSONUtil.parse(body);
        String ssoAccessToken = step5Json.getByPath("access_token").toString();
        String ssoRefreshToken = step5Json.getByPath("refresh_token").toString();
        String ssoIdToken = step5Json.getByPath("id_token").toString();
        String ssoExpiresIn = step5Json.getByPath("expires_in").toString();
        System.out.println("----------get the sso access token success!-----------");
        System.out.println("ssoAccessToken: " + ssoAccessToken);
        System.out.println("ssoRefreshToken: " + ssoRefreshToken);
        System.out.println("ssoIdToken: " + ssoIdToken);
        System.out.println("ssoExpiresIn: " + ssoExpiresIn);

        //step6 use oauth token to get vehicle access token
        HashMap<String, String> step6Headers = new HashMap<>();
        step6Headers.put("User-Agent", "Faraday v1.3.0");
        step6Headers.put("Authorization", "Bearer " + ssoAccessToken);
        Map<String, Object> step6Form = new HashMap<>();
        step6Form.put("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
        step6Form.put("client_id", "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384");
        step6Form.put("client_secret", "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3");
        HttpResponse step6Execute = HttpUtil.createPost("https://owner-api.teslamotors.com/oauth/token").addHeaders(step6Headers).form(step6Form).execute();
        String step6Body = step6Execute.body();
        JSON step6Json = JSONUtil.parse(step6Body);
        String accessToken = step6Json.getByPath("access_token").toString();
        String refreshToken = step6Json.getByPath("refresh_token").toString();
        String expiresIn = step6Json.getByPath("expires_in").toString();
        System.out.println("----------get the access token success!-----------");
        System.out.println("accessToken: " + accessToken);
        System.out.println("refreshToken: " + refreshToken);
        System.out.println("expiresIn: " + expiresIn);

    }

    private static String toCodeChallenge(String codeVerifier) {
        Digester digester = new Digester(DigestAlgorithm.SHA256);
        //sha256加密
        String sha256 = digester.digestHex(codeVerifier);
        //base64加密
        return Base64.encode(sha256);
    }

    private static String getCookie(HttpResponse execute) {
        List<String> list = execute.headers().get("Set-Cookie");
        String cookie = "";
        if (list.size() == 0) {
            throw new RuntimeException("出现异常,没有cookie!");
        }
        for (String str : list) {
            if (str.contains("tesla-auth.sid")) {
                cookie = str.split(";")[0];
            }
        }
        return cookie;
    }

    private static HashMap<String, Object> parseForm(String body) {
        Document document = Jsoup.parse(body);
        Elements inputs = document.select("input[type=hidden]");
        HashMap<String, Object> map = new HashMap<>();
        if (inputs.size() == 0) {
            System.out.println(body);
            throw new RuntimeException("出现异常!获取隐藏表单失败");
        }
        for (Element element : inputs) {
            String name = element.attr("name");
            String value = element.attr("value");
            map.put(name, value);
        }
        map.put("identity", IDENTITY);
        map.put("credential", CREDENTIAL);
        return map;
    }
}
