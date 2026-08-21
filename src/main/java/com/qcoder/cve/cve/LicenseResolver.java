package com.qcoder.cve.cve;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.qcoder.cve.model.Dependency;
import com.qcoder.cve.util.HttpUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * 组件许可协议解析：
 * Java -> Maven Central POM (优先复用 mvnrepository 抓取结果)；
 * Node.js -> npm registry；Python -> PyPI API；Rust -> crates.io API；PHP -> Packagist p2。
 */
public class LicenseResolver {

    /**
     * @param d 依赖组件
     * @param mvnRepoLicense mvnrepository 抓取到的许可（可为空）
     */
    public static String resolve(Dependency d, String mvnRepoLicense) {
        if (mvnRepoLicense != null && !mvnRepoLicense.isEmpty()) {
            return mvnRepoLicense;
        }
        switch (d.language) {
            case JAVA:
                return licenseFromMavenCentral(d);
            case NODEJS:
                return licenseFromNpm(d);
            case PYTHON:
                return licenseFromPypi(d);
            case RUST:
                return licenseFromCrates(d);
            case PHP:
                return licenseFromPackagist(d);
            default:
                return "未知";
        }
    }

    private static String licenseFromMavenCentral(Dependency d) {
        if (d.groupId.isEmpty() || d.artifactId.isEmpty() || "未知".equals(d.version) || "未锁定".equals(d.version)) {
            return "未知";
        }
        String url = "https://repo1.maven.org/maven2/" + d.groupId.replace('.', '/') + "/"
                + d.artifactId + "/" + d.version + "/" + d.artifactId + "-" + d.version + ".pom";
        try {
            String lic = parseLicenses(HttpUtil.get(url, null, 30));
            if (!"未知".equals(lic)) return lic;
            // 回退：老版本 POM 常缺 licenses 段(继承自父POM)，改用同 artifact 最新版 POM 的许可证声明
            String latest = latestVersion(d);
            if (latest != null && !latest.equals(d.version)) {
                String url2 = "https://repo1.maven.org/maven2/" + d.groupId.replace('.', '/') + "/"
                        + d.artifactId + "/" + latest + "/" + d.artifactId + "-" + latest + ".pom";
                try {
                    String lic2 = parseLicenses(HttpUtil.get(url2, null, 30));
                    if (!"未知".equals(lic2)) return lic2 + " (以版本 " + latest + " 声明为准)";
                } catch (Exception ignored) {
                }
            }
            return "未知";
        } catch (Exception e) {
            return "未知";
        }
    }

    /** 解析 POM 中的 <licenses> 段 */
    private static String parseLicenses(String pom) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (Exception ignored) {
        }
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(pom.getBytes("UTF-8")));
        NodeList licenses = doc.getElementsByTagName("license");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < licenses.getLength(); i++) {
            Element lic = (Element) licenses.item(i);
            NodeList children = lic.getChildNodes();
            String name = "", id = "";
            for (int j = 0; j < children.getLength(); j++) {
                Node n = children.item(j);
                if (n.getNodeType() == Node.ELEMENT_NODE) {
                    if ("name".equals(n.getNodeName())) name = n.getTextContent().trim();
                    if ("url".equals(n.getNodeName()) && name.isEmpty()) id = n.getTextContent().trim();
                }
            }
            String val = name.isEmpty() ? id : name;
            if (!val.isEmpty()) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(val);
            }
        }
        return sb.length() > 0 ? sb.toString() : "未知";
    }

    /** 从 maven-metadata.xml 获取该 artifact 的最新版本 */
    private static String latestVersion(Dependency d) {
        String url = "https://repo1.maven.org/maven2/" + d.groupId.replace('.', '/') + "/" + d.artifactId + "/maven-metadata.xml";
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(HttpUtil.get(url, null, 30).getBytes("UTF-8")));
            NodeList l = doc.getElementsByTagName("latest");
            return l.getLength() > 0 ? l.item(0).getTextContent().trim() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String licenseFromNpm(Dependency d) {
        String name = d.packageId;
        if (name.startsWith("@")) name = "%40" + name.substring(1).replace("/", "%2F");
        String url = "https://registry.npmjs.org/" + name + "/" + d.version;
        try {
            JsonObject root = (JsonObject) JsonParser.parseString(HttpUtil.get(url, null, 30));
            JsonElement lic = root.get("license");
            if (lic == null) return "未知";
            if (lic.isJsonPrimitive()) return lic.getAsString();
            if (lic.isJsonObject()) return lic.getAsJsonObject().has("type") ? lic.getAsJsonObject().get("type").getAsString() : "未知";
            return "未知";
        } catch (Exception e) {
            return "未知";
        }
    }

    private static String licenseFromPypi(Dependency d) {
        String url = "https://pypi.org/pypi/" + d.packageId + "/" + d.version + "/json";
        try {
            JsonObject root = (JsonObject) JsonParser.parseString(HttpUtil.get(url, null, 30));
            JsonObject info = root.has("info") ? root.getAsJsonObject("info") : null;
            if (info != null && info.has("license")) {
                String lic = info.get("license").getAsString();
                return lic == null || lic.trim().isEmpty() ? "未知(未声明)" : lic.trim();
            }
            return "未知";
        } catch (Exception e) {
            return "未知";
        }
    }

    private static String licenseFromCrates(Dependency d) {
        String url = "https://crates.io/api/v1/crates/" + d.packageId + "/" + d.version;
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("User-Agent", HttpUtil.USER_AGENT);
        try {
            JsonObject root = (JsonObject) JsonParser.parseString(HttpUtil.get(url, headers, 30));
            JsonObject crate = root.has("crate") ? root.getAsJsonObject("crate") : null;
            if (crate != null && crate.has("license")) {
                String lic = crate.get("license").getAsString();
                return lic == null || lic.trim().isEmpty() ? "未知" : lic.trim();
            }
            return "未知";
        } catch (Exception e) {
            return "未知";
        }
    }

    private static String licenseFromPackagist(Dependency d) {
        String url = "https://repo.packagist.org/p2/" + d.packageId + ".json";
        try {
            JsonObject root = (JsonObject) JsonParser.parseString(HttpUtil.get(url, null, 30));
            JsonObject pkgs = root.has("packages") ? root.getAsJsonObject("packages") : null;
            if (pkgs != null && pkgs.has(d.packageId)) {
                JsonArray versions = pkgs.getAsJsonArray(d.packageId);
                for (JsonElement e : versions) {
                    JsonObject vo = e.getAsJsonObject();
                    if (vo.has("version") && d.version.equals(vo.get("version").getAsString()) && vo.has("license")) {
                        StringBuilder sb = new StringBuilder();
                        for (JsonElement le : vo.getAsJsonArray("license")) {
                            if (sb.length() > 0) sb.append(", ");
                            sb.append(le.getAsString());
                        }
                        return sb.length() > 0 ? sb.toString() : "未知";
                    }
                }
            }
            return "未知";
        } catch (Exception e) {
            return "未知";
        }
    }
}
