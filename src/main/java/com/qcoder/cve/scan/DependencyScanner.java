package com.qcoder.cve.scan;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.qcoder.cve.ai.AiService;
import com.qcoder.cve.i18n.I18n;
import com.qcoder.cve.model.Dependency;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * 多语言项目依赖扫描器。
 * 支持：pom.xml、build.gradle、package.json、requirements.txt、Pipfile、poetry.lock、
 * go.mod、Cargo.toml、composer.json、lib 目录下的 jar 包。
 */
public class DependencyScanner {

    private static final Set<String> SKIP_DIRS = new HashSet<String>();
    static {
        String[] dirs = {".git", ".svn", "node_modules", "target", "dist", "build", "out", ".idea",
                ".vscode", "__pycache__", "venv", ".venv", ".gradle", "bin", "obj", ".mvn",
                "site", ".settings", "coverage"};
        for (String d : dirs) SKIP_DIRS.add(d.toLowerCase());
    }

    private static final Set<String> CONFIG_NAMES = new HashSet<String>();
    static {
        String[] names = {"pom.xml", "build.gradle", "build.gradle.kts", "package.json", "requirements.txt",
                "Pipfile", "poetry.lock", "go.mod", "Cargo.toml", "composer.json", "package-lock.json", "yarn.lock"};
        for (String n : names) CONFIG_NAMES.add(n);
    }

    /** 扫描结果 */
    public static class ScanResult {
        public List<Dependency> dependencies = new ArrayList<Dependency>();
        public List<String> configFiles = new ArrayList<String>();
        public String fileTree = "";
        public String aiAnalysis = "";
    }

    private static final Pattern GRADLE_DEP = Pattern.compile(
            "^\\s*(implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompileOnly|annotationProcessor|classpath|kapt|ksp)"
                    + "\\s*(?:\\(\\s*)?['\"]([^'\"]+)['\"]\\s*\\)?");
    private static final Pattern GRADLE_GROUP_NAME_VERSION = Pattern.compile(
            "group\\s*:\\s*['\"]([^'\"]+)['\"]\\s*,\\s*name\\s*:\\s*['\"]([^'\"]+)['\"]\\s*,\\s*version\\s*:\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern REQ_LINE = Pattern.compile(
            "^([A-Za-z0-9][A-Za-z0-9._\\-]*)\\s*(==|>=|<=|~=|!=|<|>)?\\s*([0-9][A-Za-z0-9.\\-_*]*)?");

    /**
     * 扫描代码项目文件夹，提取所有依赖组件。
     *
     * @param aiService 可为 null，非空且配置有效时执行 AI 项目分析与依赖补充
     */
    public static ScanResult scan(File root, AiService aiService, Consumer<String> log) {
        ScanResult result = new ScanResult();
        List<File> configFilesList = new ArrayList<File>();
        List<File> jarFiles = new ArrayList<File>();
        List<String> fileList = new ArrayList<String>();

        walk(root, root, configFilesList, jarFiles, fileList, log);

        List<Dependency> deps = new ArrayList<Dependency>();
        for (File f : configFilesList) {
            try {
                parseConfigFile(f, root, deps, log);
            } catch (Exception e) {
                log.accept(I18n.tag("log.tag.warn") + I18n.get("log.scan.configFail", f.getPath(), e.getMessage()));
            }
        }
        for (File f : jarFiles) {
            try {
                parseJarFile(f, root, deps, log);
            } catch (Exception e) {
                log.accept(I18n.tag("log.tag.warn") + I18n.get("log.scan.jarFail", f.getName(), e.getMessage()));
            }
        }

        deps = dedupeDeps(deps);

        for (File f : configFilesList) {
            result.configFiles.add(rel(root, f));
        }
        result.fileTree = buildFileTree(fileList);
        result.dependencies = deps;

        log.accept(I18n.tag("log.tag.scan") + I18n.get("log.scan.done", result.configFiles.size(), deps.size()));

        applyAiAnalysis(root, aiService, result, log);
        return result;
    }

    /** 按 语言+packageId+版本 去重，合并来源文件 */
    private static List<Dependency> dedupeDeps(List<Dependency> deps) {
        Map<String, Dependency> unique = new HashMap<String, Dependency>();
        List<Dependency> deduped = new ArrayList<Dependency>();
        for (Dependency d : deps) {
            String key = d.language.name() + "|" + d.packageId + "|" + d.version;
            Dependency exist = unique.get(key);
            if (exist == null) {
                unique.put(key, d);
                deduped.add(d);
            } else {
                if (exist.sourceFile.indexOf(d.sourceFile) < 0) {
                    exist.sourceFile = exist.sourceFile + "; " + d.sourceFile;
                }
            }
        }
        return deduped;
    }

    /** AI 项目分析与依赖补充（三种扫描模式共用） */
    private static void applyAiAnalysis(File root, AiService aiService, ScanResult result, Consumer<String> log) {
        if (aiService == null) return;
        log.accept(I18n.tag("log.tag.ai") + I18n.get("log.ai.start", aiService.getClient().getModel()));
        long t0 = System.currentTimeMillis();
        AiService.AnalysisResult ar = aiService.analyzeProject(root, result.configFiles, result.dependencies);
        long cost = (System.currentTimeMillis() - t0) / 1000;
        if (ar.analysis.startsWith("AI 项目分析调用失败")) {
            log.accept(I18n.tag("log.tag.ai") + I18n.get("log.ai.fail", ar.analysis));
        } else if (!ar.analysis.isEmpty()) {
            result.aiAnalysis = ar.analysis;
            log.accept(I18n.tag("log.tag.ai") + I18n.get("log.ai.done", cost));
        }
        int added = 0;
        for (Dependency extra : ar.extraDependencies) {
            boolean dup = false;
            for (Dependency d : result.dependencies) {
                if (d.language == extra.language && d.packageId.equals(extra.packageId) && d.version.equals(extra.version)) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                result.dependencies.add(extra);
                added++;
            }
        }
        if (added > 0) {
            log.accept(I18n.tag("log.tag.ai") + I18n.get("log.ai.added", added));
        }
    }

    /**
     * 模式一：扫描单个 lib 文件夹，解析其中所有 jar 包生成依赖清单。
     */
    public static ScanResult scanLibFolder(File libDir, AiService aiService, Consumer<String> log) {
        ScanResult result = new ScanResult();
        List<File> jars = new ArrayList<File>();
        collectJars(libDir, jars);
        List<Dependency> deps = new ArrayList<Dependency>();
        List<String> fileList = new ArrayList<String>();
        for (File f : jars) {
            parseJarFile(f, libDir, deps, log);
            if (fileList.size() < 300) fileList.add(rel(libDir, f));
        }
        result.dependencies = dedupeDeps(deps);
        result.fileTree = buildFileTree(fileList);
        log.accept(I18n.tag("log.tag.scan") + I18n.get("log.scan.lib", jars.size(), result.dependencies.size()));
        applyAiAnalysis(libDir, aiService, result, log);
        return result;
    }

    /**
     * 模式二：读取 jar/war 打包文件，解析包内 lib 文件夹中的 jar 包生成依赖清单。
     * 支持 web 应用的 WEB-INF/lib、SpringBoot 的 BOOT-INF/lib 等目录结构。
     */
    public static ScanResult scanArchive(File archive, AiService aiService, Consumer<String> log) {
        ScanResult result = new ScanResult();
        List<Dependency> deps = new ArrayList<Dependency>();
        List<String> fileList = new ArrayList<String>();
        String project = archive.getName();
        int libCount = 0;
        ZipFile zf = null;
        try {
            zf = new ZipFile(archive);
            java.util.Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String n = e.getName();
                if (e.isDirectory() || !n.endsWith(".jar")) continue;
                String slashed = n.replace('\\', '/');
                if (!slashed.startsWith("lib/") && !slashed.contains("/lib/")) continue;
                byte[] content = readAll(zf.getInputStream(e));
                parseJarBytes(basename(slashed), content, project, deps, log);
                if (fileList.size() < 300) fileList.add(n);
                libCount++;
            }
        } catch (Exception e) {
            log.accept(I18n.tag("log.tag.warn") + I18n.get("log.scan.warnArchive", archive.getName(), e.getMessage()));
        } finally {
            if (zf != null) {
                try {
                    zf.close();
                } catch (IOException ignored) {
                }
            }
        }
        result.dependencies = dedupeDeps(deps);
        result.fileTree = buildFileTree(fileList);
        log.accept(I18n.tag("log.tag.scan") + I18n.get("log.scan.archive", libCount, result.dependencies.size()));
        applyAiAnalysis(archive, aiService, result, log);
        return result;
    }

    private static void collectJars(File dir, List<File> jars) {
        File[] children = dir.listFiles();
        if (children == null) return;
        for (File f : children) {
            if (f.isDirectory()) {
                if (SKIP_DIRS.contains(f.getName().toLowerCase())) continue;
                collectJars(f, jars);
            } else if (f.getName().endsWith(".jar")) {
                jars.add(f);
            }
        }
    }

    private static void walk(File root, File dir, List<File> configFiles, List<File> jarFiles,
                             List<String> fileList, Consumer<String> log) {
        File[] children = dir.listFiles();
        if (children == null) return;
        for (File f : children) {
            if (f.isDirectory()) {
                if (SKIP_DIRS.contains(f.getName().toLowerCase())) continue;
                walk(root, f, configFiles, jarFiles, fileList, log);
            } else {
                String name = f.getName();
                if (CONFIG_NAMES.contains(name)) {
                    configFiles.add(f);
                } else if (name.endsWith(".jar") && isLibPath(f)) {
                    jarFiles.add(f);
                } else if (name.endsWith(".jar") && name.length() < 120) {
                    // lib 目录之外的 jar 也尝试解析（如资源目录）
                    jarFiles.add(f);
                }
                if (fileList.size() < 300) {
                    fileList.add(rel(root, f));
                }
            }
        }
    }

    private static boolean isLibPath(File f) {
        String p = f.getParent() == null ? "" : f.getParent().toLowerCase();
        return p.endsWith("lib") || p.endsWith("libs") || p.contains("web-inf/lib") || p.contains("boot-inf/lib");
    }

    private static String buildFileTree(List<String> fileList) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < fileList.size(); i++) {
            sb.append(fileList.get(i)).append("\n");
        }
        if (sb.length() == 0) sb.append("(空目录)");
        return sb.toString();
    }

    // ---------------- 配置文件解析 ----------------

    private static void parseConfigFile(File f, File root, List<Dependency> out, Consumer<String> log) throws Exception {
        String name = f.getName();
        String project = rel(root, f.getParentFile());
        if ("pom.xml".equals(name)) {
            parsePom(f, root, project, out, log);
        } else if ("build.gradle".equals(name) || "build.gradle.kts".equals(name)) {
            parseGradle(f, project, out);
        } else if ("package.json".equals(name)) {
            parsePackageJson(f, project, out);
        } else if ("requirements.txt".equals(name)) {
            parseRequirements(f, project, out);
        } else if ("Pipfile".equals(name)) {
            parsePipfile(f, project, out);
        } else if ("poetry.lock".equals(name)) {
            parsePoetryLock(f, project, out);
        } else if ("go.mod".equals(name)) {
            parseGoMod(f, project, out);
        } else if ("Cargo.toml".equals(name)) {
            parseCargo(f, project, out);
        } else if ("composer.json".equals(name)) {
            parseComposer(f, project, out);
        } else if ("package-lock.json".equals(name) || "yarn.lock".equals(name)) {
            // 锁文件：版本以 package.json 为准，此处仅登记来源
            log.accept(I18n.tag("log.tag.tip") + I18n.get("log.scan.lockHint", rel(root, f)));
        }
    }

    /** 解析 pom.xml（含 ${property} 版本变量解析） */
    private static void parsePom(File f, File root, String project, List<Dependency> out, Consumer<String> log) throws Exception {
        byte[] bytes = Files.readAllBytes(f.toPath());
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        dbf.setExpandEntityReferences(false);
        try {
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        } catch (Exception ignored) {
        }
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(bytes));

        Element rootEl = doc.getDocumentElement();
        Map<String, String> props = new HashMap<String, String>();
        Element propsEl = directChild(rootEl, "properties");
        if (propsEl != null) {
            NodeList children = propsEl.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                Node n = children.item(i);
                if (n.getNodeType() == Node.ELEMENT_NODE) {
                    props.put(n.getNodeName(), n.getTextContent().trim());
                }
            }
        }
        Element parentEl = directChild(rootEl, "parent");
        String parentGroup = parentEl == null ? "" : textOf(directChild(parentEl, "groupId"));
        String parentVersion = parentEl == null ? "" : textOf(directChild(parentEl, "version"));
        String projGroup = textOf(directChild(rootEl, "groupId"));
        if (projGroup.isEmpty()) projGroup = parentGroup;
        String projVersion = textOf(directChild(rootEl, "version"));
        if (projVersion.isEmpty()) projVersion = parentVersion;
        String packaging = textOf(directChild(rootEl, "packaging"));

        NodeList deps = rootEl.getElementsByTagName("dependency");
        for (int i = 0; i < deps.getLength(); i++) {
            Element dep = (Element) deps.item(i);
            String g = textOf(directChild(dep, "groupId"));
            String a = textOf(directChild(dep, "artifactId"));
            if (g.isEmpty() || a.isEmpty()) continue;
            String v = textOf(directChild(dep, "version"));
            if (v.isEmpty()) {
                // 未声明版本：可能由 dependencyManagement 或父POM 管理
                v = "(由dependencyManagement管理)";
            }
            String scope = textOf(directChild(dep, "scope"));
            if (scope.isEmpty()) scope = "compile";
            String optional = textOf(directChild(dep, "optional"));

            Dependency d = new Dependency();
            d.language = Dependency.Language.JAVA;
            d.groupId = g;
            d.artifactId = a;
            d.packageId = g + ":" + a;
            d.scope = scope;
            d.sourceFile = f.getAbsolutePath();
            d.projectName = project;
            String resolved = resolveVersion(v, props);
            if (!resolved.equals(v)) {
                d.version = resolved;
            } else if (v.startsWith("${")) {
                d.version = v;
                d.versionVariable = true;
            } else {
                d.version = v;
            }
            if (d.version.contains("${")) d.versionVariable = true;
            String type = "Maven依赖";
            if ("test".equals(scope)) type = "Maven依赖(test)";
            else if ("provided".equals(scope)) type = "Maven依赖(provided)";
            else if ("runtime".equals(scope)) type = "Maven依赖(runtime)";
            if ("true".equals(optional)) type += "(optional)";
            d.introduceType = type;
            out.add(d);
        }
        if ("pom".equals(packaging)) {
            log.accept(I18n.tag("log.tag.tip") + I18n.get("log.scan.pomHint", rel(root, f)));
        }
    }

    private static String resolveVersion(String v, Map<String, String> props) {
        if (v == null || !v.contains("${")) return v == null ? "" : v;
        String resolved = v;
        Matcher m = Pattern.compile("\\$\\{([^}]+)}").matcher(v);
        while (m.find()) {
            String key = m.group(1);
            String val = props.get(key);
            if (val == null && "project.version".equals(key)) val = ""; // 项目自身版本，与依赖无关
            if (val != null) {
                resolved = resolved.replace(m.group(0), val);
            }
        }
        return resolved;
    }

    private static void parseGradle(File f, String project, List<Dependency> out) throws IOException {
        String content = readFileSmart(f);
        for (String line : content.split("\r?\n")) {
            Matcher m = GRADLE_GROUP_NAME_VERSION.matcher(line);
            if (m.find()) {
                addDep(out, Dependency.Language.JAVA, m.group(1), m.group(2), m.group(3),
                        "Gradle依赖", f.getAbsolutePath(), project, "compile", false);
                continue;
            }
            m = GRADLE_DEP.matcher(line);
            if (m.find()) {
                String cfg = m.group(1);
                String coord = m.group(2);
                if (coord.contains(":") && !coord.contains("project(") && !coord.contains("files(")) {
                    String[] parts = coord.split(":");
                    if (parts.length >= 3) {
                        addDep(out, Dependency.Language.JAVA, parts[0], parts[1], parts[2],
                                "Gradle依赖(" + cfg + ")", f.getAbsolutePath(), project, cfg, parts[2].contains("$"));
                    }
                }
            }
        }
    }

    private static void parsePackageJson(File f, String project, List<Dependency> out) throws IOException {
        JsonObject root = (JsonObject) JsonParser.parseString(readFileSmart(f));
        String[][] sections = {{"dependencies", "npm依赖"}, {"devDependencies", "npm依赖(dev)"},
                {"optionalDependencies", "npm依赖(optional)"}, {"peerDependencies", "npm依赖(peer)"}};
        for (String[] sec : sections) {
            JsonElement el = root.get(sec[0]);
            if (el == null || !el.isJsonObject()) continue;
            for (Map.Entry<String, JsonElement> e : el.getAsJsonObject().entrySet()) {
                String name = e.getKey();
                String ver = e.getValue().getAsString().trim();
                if (ver.isEmpty() || ver.startsWith("workspace:") || ver.startsWith("file:") || ver.startsWith("link:") || ver.startsWith("npm:")) {
                    continue;
                }
                // ^/~ 前缀清理后即为可用的声明版本；其余为范围/未锁定版本
                if (ver.startsWith("^") || ver.startsWith("~")) {
                    addDep(out, Dependency.Language.NODEJS, "", name, cleanVersion(ver),
                            sec[1], f.getAbsolutePath(), project, "", false);
                } else if (ver.startsWith(">") || ver.startsWith("<") || ver.startsWith("=") || ver.startsWith("*") || ver.contains("||")) {
                    addDep(out, Dependency.Language.NODEJS, "", name, ver,
                            sec[1], f.getAbsolutePath(), project, "", true);
                } else {
                    addDep(out, Dependency.Language.NODEJS, "", name, ver,
                            sec[1], f.getAbsolutePath(), project, "", false);
                }
            }
        }
    }

    private static void parseRequirements(File f, String project, List<Dependency> out) throws IOException {
        String content = readFileSmart(f);
        for (String line : content.split("\r?\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            if (t.startsWith("-r ") || t.startsWith("--requirement") || t.startsWith("--index-url") || t.startsWith("-i ") || t.startsWith("-e ") || t.startsWith("--extra-index-url")) {
                continue;
            }
            Matcher m = REQ_LINE.matcher(t);
            if (m.find()) {
                String name = m.group(1);
                String op = m.group(2);
                String ver = m.group(3);
                if (op == null || op.isEmpty()) {
                    addDep(out, Dependency.Language.PYTHON, "", name, "未锁定",
                            "pip依赖(requirements.txt)", f.getAbsolutePath(), project, "", true);
                } else if ("==".equals(op)) {
                    addDep(out, Dependency.Language.PYTHON, "", name, ver == null ? "未锁定" : ver,
                            "pip依赖(requirements.txt)", f.getAbsolutePath(), project, "", false);
                } else {
                    // 范围版本(>=,<=,~=,!=等)仅展示，不参与漏洞查询
                    addDep(out, Dependency.Language.PYTHON, "", name, op + (ver == null ? "" : ver),
                            "pip依赖(requirements.txt)", f.getAbsolutePath(), project, "", true);
                }
            }
        }
    }

    private static void parsePipfile(File f, String project, List<Dependency> out) throws IOException {
        String content = readFileSmart(f);
        String section = "";
        Pattern p = Pattern.compile("^\\s*([A-Za-z0-9_.\\-]+)\\s*=\\s*(?:(\\{[^}]*version\\s*=\\s*)?[\"']?([^\"'\\}\\s]+)[\"']?");
        for (String line : content.split("\r?\n")) {
            String t = line.trim();
            if (t.startsWith("[")) {
                section = t;
                continue;
            }
            if (t.isEmpty() || t.startsWith("#")) continue;
            Matcher m = p.matcher(t);
            if (m.find()) {
                String name = m.group(1);
                String ver = m.group(3) == null ? "" : m.group(3).trim();
                if (ver.isEmpty() || "*".equals(ver)) {
                    addDep(out, Dependency.Language.PYTHON, "", name, "未锁定",
                            "pip依赖(Pipfile" + section + ")", f.getAbsolutePath(), project, "", true);
                } else {
                    boolean var = !ver.startsWith("=") && !ver.matches("^\\d.*");
                    addDep(out, Dependency.Language.PYTHON, "", name, cleanVersion(ver),
                            "pip依赖(Pipfile" + section + ")", f.getAbsolutePath(), project, "", var);
                }
            }
        }
    }

    private static void parsePoetryLock(File f, String project, List<Dependency> out) throws IOException {
        String content = readFileSmart(f);
        String name = "", version = "";
        for (String line : content.split("\r?\n")) {
            String t = line.trim();
            if (t.startsWith("[[package]]")) {
                if (!name.isEmpty() && !version.isEmpty()) {
                    addDep(out, Dependency.Language.PYTHON, "", name, version,
                            "pip依赖(poetry.lock)", f.getAbsolutePath(), project, "", false);
                }
                name = "";
                version = "";
            } else if (t.startsWith("name = ")) {
                name = t.replace("name = ", "").replace("\"", "").trim();
            } else if (t.startsWith("version = ")) {
                version = t.replace("version = ", "").replace("\"", "").trim();
            }
        }
        if (!name.isEmpty() && !version.isEmpty()) {
            addDep(out, Dependency.Language.PYTHON, "", name, version,
                    "pip依赖(poetry.lock)", f.getAbsolutePath(), project, "", false);
        }
    }

    private static void parseGoMod(File f, String project, List<Dependency> out) throws IOException {
        String content = readFileSmart(f);
        boolean inBlock = false;
        for (String line : content.split("\r?\n")) {
            String t = line.trim();
            if (t.startsWith("require (")) {
                inBlock = true;
                continue;
            }
            if (inBlock && t.startsWith(")")) {
                inBlock = false;
                continue;
            }
            if (inBlock || t.startsWith("require ")) {
                String req = t.startsWith("require ") ? t.substring("require ".length()).trim() : t;
                if (req.isEmpty() || req.startsWith("(")) continue;
                String[] parts = req.split("\\s+");
                if (parts.length >= 2 && parts[1].matches("v\\d.*")) {
                    boolean indirect = req.contains("// indirect");
                    addDep(out, Dependency.Language.GO, "", parts[0], parts[1],
                            indirect ? "Go间接依赖" : "Go模块依赖", f.getAbsolutePath(), project, "", false);
                }
            }
        }
    }

    private static void parseCargo(File f, String project, List<Dependency> out) throws IOException {
        String content = readFileSmart(f);
        String section = "";
        for (String line : content.split("\r?\n")) {
            String t = line.trim();
            if (t.startsWith("[")) {
                section = t;
                continue;
            }
            if (!section.startsWith("[dependencies") && !section.startsWith("[dev-dependencies")) continue;
            if (t.isEmpty() || t.startsWith("#")) continue;
            Matcher m = Pattern.compile("^([A-Za-z0-9_\\-]+)\\s*=\\s*(?:\\{[^}]*)?[\"']?([0-9][^\"'}]*)?[\"']?").matcher(t);
            if (m.find() && m.group(2) != null) {
                boolean dev = section.startsWith("[dev-dependencies");
                addDep(out, Dependency.Language.RUST, "", m.group(1), m.group(2).trim(),
                        dev ? "Cargo依赖(dev)" : "Cargo依赖", f.getAbsolutePath(), project, "", false);
            }
        }
    }

    private static void parseComposer(File f, String project, List<Dependency> out) throws IOException {
        JsonObject root = (JsonObject) JsonParser.parseString(readFileSmart(f));
        String[][] sections = {{"require", "Composer依赖"}, {"require-dev", "Composer依赖(dev)"}};
        for (String[] sec : sections) {
            JsonElement el = root.get(sec[0]);
            if (el == null || !el.isJsonObject()) continue;
            for (Map.Entry<String, JsonElement> e : el.getAsJsonObject().entrySet()) {
                String ver = e.getValue().getAsString().trim();
                if (ver.startsWith("dev-") || ver.startsWith("self.version")) continue;
                if (ver.startsWith("^") || ver.startsWith("~")) {
                    addDep(out, Dependency.Language.PHP, "", e.getKey(), cleanVersion(ver),
                            sec[1], f.getAbsolutePath(), project, "", false);
                } else {
                    addDep(out, Dependency.Language.PHP, "", e.getKey(), ver,
                            sec[1], f.getAbsolutePath(), project, "", ver.startsWith(">") || ver.startsWith("<") || ver.startsWith("*"));
                }
            }
        }
    }

    /** 解析 lib 目录下的 jar 包：优先读 META-INF/maven 下的 pom.properties，其次 pom.xml，最后按文件名推断 */
    private static void parseJarFile(File f, File root, List<Dependency> out, Consumer<String> log) {
        String project = rel(root, f.getParentFile());
        try {
            parseJarBytes(f.getName(), Files.readAllBytes(f.toPath()), project, out, log);
        } catch (Exception e) {
            log.accept(I18n.tag("log.tag.warn") + I18n.get("log.scan.warnJar", f.getName(), e.getMessage()));
        }
    }
    
    /** 从 jar 字节内容解析组件坐标（支持文件 jar 与 jar/war 包内嵌 jar） */
    private static void parseJarBytes(String jarName, byte[] content, String project, List<Dependency> out, Consumer<String> log) {
        String g = "", a = "", v = "";
        try {
            ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content));
            byte[] propsBytes = null, pomBytes = null;
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                String n = e.getName();
                if (n.startsWith("META-INF/maven/") && n.endsWith("/pom.properties") && propsBytes == null) {
                    propsBytes = readAll(zis);
                } else if (n.startsWith("META-INF/maven/") && n.endsWith("/pom.xml") && pomBytes == null) {
                    pomBytes = readAll(zis);
                }
            }
            zis.close();
            if (propsBytes != null) {
                Properties props = new Properties();
                props.load(new ByteArrayInputStream(propsBytes));
                g = props.getProperty("groupId", "");
                a = props.getProperty("artifactId", "");
                v = props.getProperty("version", "");
            }
            if (a.isEmpty() && pomBytes != null) {
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(pomBytes));
                Element rootEl = doc.getDocumentElement();
                g = textOf(directChild(rootEl, "groupId"));
                a = textOf(directChild(rootEl, "artifactId"));
                v = textOf(directChild(rootEl, "version"));
            }
            if (a.isEmpty()) {
                // 按文件名推断 name-version.jar
                Matcher m = Pattern.compile("^(.+?)-(\\d[\\w.\\-]*)\\.jar$").matcher(jarName);
                if (m.find()) {
                    a = m.group(1);
                    v = m.group(2);
                } else {
                    a = jarName.replace(".jar", "");
                    v = "未知";
                }
            }
            addDep(out, Dependency.Language.JAVA, g, a, v.isEmpty() ? "未知" : v,
                    "本地Jar包(lib目录)", jarName, project, "lib", v.isEmpty());
        } catch (Exception e) {
            log.accept(I18n.tag("log.tag.warn") + I18n.get("log.scan.warnParse", jarName, e.getMessage()));
        }
    }
    
    /** 读取输入流全部字节 */
    private static byte[] readAll(java.io.InputStream in) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }
    
    /** 取路径最后一段（去掉目录部分） */
    private static String basename(String path) {
        int idx = path.lastIndexOf('/');
        return idx >= 0 ? path.substring(idx + 1) : path;
    }

    private static void addDep(List<Dependency> out, Dependency.Language lang, String group, String artifact,
                               String version, String type, String source, String project, String scope, boolean versionVar) {
        Dependency d = new Dependency();
        d.language = lang;
        d.groupId = group == null ? "" : group;
        d.artifactId = artifact == null ? "" : artifact;
        d.packageId = d.groupId.isEmpty() ? d.artifactId : d.groupId + ":" + d.artifactId;
        d.version = (version == null || version.isEmpty()) ? "未锁定" : version;
        d.versionVariable = versionVar;
        d.introduceType = type;
        d.sourceFile = source;
        d.projectName = project;
        d.scope = scope;
        out.add(d);
    }

    // ---------------- 工具方法 ----------------

    private static Element directChild(Element parent, String name) {
        if (parent == null) return null;
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE && name.equals(n.getNodeName())) {
                return (Element) n;
            }
        }
        return null;
    }

    private static String textOf(Element el) {
        return el == null ? "" : el.getTextContent().trim();
    }

    private static String cleanVersion(String v) {
        String t = v == null ? "" : v.trim().replace("\"", "").replace("'", "");
        t = t.replaceFirst("^[\\^~]", "");
        if (t.isEmpty() || t.contains(">") || t.contains("<") || t.contains("=") || t.contains("*") || t.contains("||") || t.contains(" ")) {
            return v == null ? "未锁定" : v.trim();
        }
        return t.isEmpty() ? "未锁定" : t;
    }

    /** 智能读取文本文件：优先 UTF-8，失败回退 GBK（兼容中文 Windows 源码） */
    private static String readFileSmart(File f) throws IOException {
        byte[] bytes = Files.readAllBytes(f.toPath());
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            return new String(bytes, Charset.forName("GBK"));
        }
    }

    private static String rel(File root, File f) {
        String rp = root.getAbsolutePath().replace('\\', '/');
        String fp = f.getAbsolutePath().replace('\\', '/');
        if (fp.startsWith(rp)) {
            return fp.substring(rp.length()).replaceFirst("^/+", "");
        }
        return fp;
    }
}
