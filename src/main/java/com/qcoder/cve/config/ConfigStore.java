package com.qcoder.cve.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

/** 配置文件读写：config/app-config.json */
public class ConfigStore {

    public static File getConfigFile() {
        return new File("config/app-config.json");
    }

    public static AppConfig load() {
        AppConfig cfg = new AppConfig();
        File f = getConfigFile();
        if (f.exists()) {
            try {
                InputStreamReader reader = new InputStreamReader(new FileInputStream(f), java.nio.charset.StandardCharsets.UTF_8);
                AppConfig loaded = new Gson().fromJson(reader, AppConfig.class);
                reader.close();
                if (loaded != null) cfg = loaded;
            } catch (Exception e) {
                System.err.println("加载配置文件失败: " + e.getMessage());
            }
        }
        cfg.normalize();
        return cfg;
    }

    public static void save(AppConfig cfg) throws IOException {
        File f = getConfigFile();
        File parent = f.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(f), java.nio.charset.StandardCharsets.UTF_8);
        gson.toJson(cfg, writer);
        writer.close();
    }
}
