package com.qcoder.cve.ai;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.qcoder.cve.util.HttpUtil;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * OpenAI 兼容的 Chat Completions 客户端。
 * 外网模型(OpenAI/DeepSeek等)与内网模型(Ollama/私有网关)均适用。
 */
public class AiClient {

    private final String baseUrl;
    private final String apiKey;
    private final String model;
    private final int timeoutSec;

    public AiClient(String baseUrl, String apiKey, String model, int timeoutSec) {
        this.baseUrl = baseUrl == null ? "" : baseUrl.trim();
        this.apiKey = apiKey == null ? "" : apiKey.trim();
        this.model = model == null ? "" : model.trim();
        this.timeoutSec = timeoutSec > 0 ? timeoutSec : 60;
    }

    public String getModel() {
        return model;
    }

    public boolean isConfigured() {
        return !baseUrl.isEmpty() && !model.isEmpty();
    }

    /** 调用 chat/completions，返回回复文本 */
    public String chat(String systemPrompt, String userPrompt) throws IOException {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", model);
        JsonArray messages = new JsonArray();
        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            JsonObject sys = new JsonObject();
            sys.addProperty("role", "system");
            sys.addProperty("content", systemPrompt);
            messages.add(sys);
        }
        JsonObject user = new JsonObject();
        user.addProperty("role", "user");
        user.addProperty("content", userPrompt);
        messages.add(user);
        payload.add("messages", messages);
        payload.addProperty("temperature", 0.2);
        payload.addProperty("max_tokens", 4096);

        String url = baseUrl;
        if (!url.endsWith("/")) url += "/";
        url += "chat/completions";

        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/json");
        if (!apiKey.isEmpty()) {
            headers.put("Authorization", "Bearer " + apiKey);
        }
        String resp = HttpUtil.postJson(url, payload.toString(), headers, timeoutSec);
        JsonObject root = (JsonObject) JsonParser.parseString(resp);
        JsonArray choices = root.getAsJsonArray("choices");
        if (choices == null || choices.size() == 0) {
            throw new IOException("AI 返回内容中没有 choices: " + HttpUtil.truncate(resp, 200));
        }
        JsonObject message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
        if (message == null || !message.has("content")) {
            throw new IOException("AI 返回内容中没有 message.content");
        }
        return message.get("content").getAsString();
    }

    /** 连通性测试 */
    public String ping() throws IOException {
        return chat(null, "请只回复四个字：连接成功");
    }
}
