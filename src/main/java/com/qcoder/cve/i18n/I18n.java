package com.qcoder.cve.i18n;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;

/**
 * 国际化支持：运行时切换语言，界面 / 日志 / Excel 文本统一从此读取。
 * 资源文件位于 resources/i18n/messages_{lang}.properties，UTF-8 编码，{0}{1} 占位符。
 */
public class I18n {

    public static final String ZH = "zh";
    public static final String EN = "en";
    public static final String FR = "fr";
    public static final String JA = "ja";

    private static volatile Map<String, String> bundle = load(ZH);

    private I18n() {
    }

    /** 切换语言（zh/en/fr/ja），未知语言回退中文 */
    public static void setLanguage(String lang) {
        String l = (lang == null || lang.isEmpty()) ? ZH : lang.toLowerCase();
        bundle = load(l);
    }

    public static String lang() {
        String l = "";
        String v = bundle.get("_lang");
        if (v != null) l = v;
        return l.isEmpty() ? ZH : l;
    }

    /** 取翻译文本 */
    public static String get(String key) {
        String v = bundle.get(key);
        return v == null ? key : v;
    }

    /** 取翻译文本并格式化占位符 */
    public static String get(String key, Object... args) {
        String v = get(key);
        try {
            return MessageFormat.format(v, args);
        } catch (Exception e) {
            return v;
        }
    }

    /** 日志分类标签：如 tag("log.tag.warn") 返回 [警告] */
    public static String tag(String key) {
        return "[" + get(key) + "] ";
    }

    /** 严重等级内部码 -> 当前语言显示文本（内部码固定为中文常量） */
    public static String severity(String internal) {
        if ("严重".equals(internal)) return get("sev.critical");
        if ("高危".equals(internal)) return get("sev.high");
        if ("中危".equals(internal)) return get("sev.medium");
        if ("低危".equals(internal)) return get("sev.low");
        return get("sev.unknown");
    }

    /** 通用数据值本地化（未知/未锁定/未知(未声明) 等内部码 -> 当前语言文本） */
    public static String localizeValue(String internal) {
        if (internal == null || internal.isEmpty()) return "";
        if ("未知".equals(internal)) return get("common.unknown");
        if ("未知(未声明)".equals(internal)) return get("common.undeclared");
        if ("未锁定".equals(internal)) return get("common.unlocked");
        if ("是".equals(internal)) return get("common.yes");
        if ("否".equals(internal)) return get("common.no");
        if ("未查询".equals(internal)) return get("common.notQueried");
        return internal;
    }

    /** 查询状态内部码 -> 当前语言显示文本 */
    public static String localizeStatus(String s) {
        if (s == null || s.isEmpty()) return s;
        if ("成功".equals(s)) return get("common.success");
        if ("无有效版本(未锁定/变量)，跳过漏洞查询".equals(s)) return get("common.skipNoVersion");
        if ("所有查询方式均未成功".equals(s)) return get("common.allFailed");
        if ("OSS Index 未返回该组件结果".equals(s)) return get("common.notFound", "OSS Index");
        if ("OSV 未返回该组件结果".equals(s)) return get("common.notFound", "OSV.dev");
        if ("IQ Server 未返回该组件结果".equals(s)) return get("common.notFound", "IQ Server");
        if ("未配置 IQ Server 服务器地址".equals(s)) return get("query.iqNotConfigured");
        if (s.startsWith("mvnrepository查询失败: ")) return I18n.get("log.query.mvnFail2", s.substring("mvnrepository查询失败: ".length()));
        if (s.startsWith("成功(") && s.endsWith(")")) return get("common.success") + "(" + s.substring(3, s.length() - 1) + ")";
        return localizeValue(s);
    }

    private static Map<String, String> load(String lang) {
        Map<String, String> map = new HashMap<String, String>();
        map.put("_lang", lang);
        loadInto(map, "i18n/messages_" + lang + ".properties");
        if (!ZH.equals(lang)) {
            // 缺失键回退中文
            Map<String, String> fallback = new HashMap<String, String>();
            loadInto(fallback, "i18n/messages_zh.properties");
            for (Map.Entry<String, String> e : fallback.entrySet()) {
                if (!map.containsKey(e.getKey())) map.put(e.getKey(), e.getValue());
            }
        }
        return map;
    }

    private static void loadInto(Map<String, String> map, String path) {
        InputStream in = I18n.class.getClassLoader().getResourceAsStream(path);
        if (in == null) return;
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(in, "UTF-8"));
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int idx = line.indexOf('=');
                if (idx <= 0) continue;
                map.put(line.substring(0, idx).trim(), unescape(line.substring(idx + 1).trim()));
            }
            r.close();
        } catch (Exception e) {
            // 资源缺失时使用已加载内容
        }
    }

    /** properties 单行值中的 \n 转义为真实换行 */
    private static String unescape(String s) {
        return s.indexOf("\\n") >= 0 ? s.replace("\\n", "\n") : s;
    }
}
