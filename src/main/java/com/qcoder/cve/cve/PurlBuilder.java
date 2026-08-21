package com.qcoder.cve.cve;

import com.qcoder.cve.model.Dependency;

/** 将依赖组件转换为 Package URL (purl) 标准坐标 */
public final class PurlBuilder {

    private PurlBuilder() {
    }

    /**
     * 生成 purl，如 pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1。
     * 版本未锁定或未知时返回 null。
     */
    public static String toPurl(Dependency d) {
        String v = d.version;
        if (v == null || v.isEmpty() || "未锁定".equals(v) || "未知".equals(v) || d.versionVariable) {
            return null;
        }
        v = v.trim();
        switch (d.language) {
            case JAVA: {
                if (d.groupId.isEmpty() || d.artifactId.isEmpty()) return null;
                return "pkg:maven/" + d.groupId + "/" + d.artifactId + "@" + v;
            }
            case NODEJS: {
                String name = d.packageId;
                if (name.startsWith("@")) {
                    name = "%40" + name.substring(1).replace("/", "%2F");
                }
                return "pkg:npm/" + name + "@" + v;
            }
            case PYTHON:
                return "pkg:pypi/" + d.packageId + "@" + v;
            case GO:
                return "pkg:golang/" + d.packageId + "@" + v;
            case RUST:
                return "pkg:cargo/" + d.packageId + "@" + v;
            case PHP:
                return "pkg:composer/" + d.packageId + "@" + v;
            default:
                return null;
        }
    }

    /** mvnrepository 页面 URL：https://mvnrepository.com/artifact/{groupId}/{artifactId}/{version} */
    public static String toMvnRepoUrl(Dependency d) {
        if (d.groupId.isEmpty() || d.artifactId.isEmpty()) return null;
        return "https://mvnrepository.com/artifact/" + d.groupId + "/" + d.artifactId + "/" + d.version;
    }
}
