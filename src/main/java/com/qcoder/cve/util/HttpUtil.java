package com.qcoder.cve.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;

/** 基于 HttpURLConnection 的轻量 HTTP 工具（兼容 JDK 8） */
public final class HttpUtil {

    public static final String USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 CveScanner/1.0";

    private HttpUtil() {
    }

    public static String get(String url, Map<String, String> headers, int timeoutSec) throws IOException {
        return request("GET", url, null, headers, timeoutSec);
    }

    public static String postJson(String url, String jsonBody, Map<String, String> headers, int timeoutSec) throws IOException {
        return request("POST", url, jsonBody, headers, timeoutSec);
    }

    private static String request(String method, String url, String body, Map<String, String> headers, int timeoutSec) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(timeoutSec * 1000);
        conn.setReadTimeout(timeoutSec * 1000);
        conn.setRequestProperty("User-Agent", USER_AGENT);
        conn.setRequestProperty("Accept", "*/*");
        conn.setRequestProperty("Accept-Encoding", "identity");
        conn.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8");
        conn.setRequestProperty("Connection", "close");
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                conn.setRequestProperty(e.getKey(), e.getValue());
            }
        }
        if (body != null) {
            conn.setDoOutput(true);
            if (conn.getRequestProperty("Content-Type") == null) {
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            }
            OutputStream os = conn.getOutputStream();
            os.write(body.getBytes("UTF-8"));
            os.flush();
            os.close();
        }
        int code = conn.getResponseCode();
        InputStream in = (code >= 400) ? conn.getErrorStream() : conn.getInputStream();
        if (in == null) in = conn.getErrorStream();
        String resp = (in == null) ? "" : readAll(in);
        if (code >= 400) {
            throw new IOException("HTTP " + code + ": " + truncate(resp, 300) + "  (URL: " + url + ")");
        }
        return resp;
    }

    private static String readAll(InputStream in) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
        StringBuilder sb = new StringBuilder();
        char[] buf = new char[4096];
        int n;
        while ((n = reader.read(buf)) != -1) {
            sb.append(buf, 0, n);
        }
        reader.close();
        return sb.toString();
    }

    public static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
