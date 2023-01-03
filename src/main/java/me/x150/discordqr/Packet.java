package me.x150.discordqr;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.HashMap;
import java.util.Map;

class Packet {
    public String op;
    public Map<String, JsonElement> data;

    public Packet(JsonObject obj) {
        this.op = obj.get("op").getAsString();
        this.data = new HashMap<>();
        for (String s : obj.keySet()) {
            if (s.equals("op")) {
                continue;
            }
            data.put(s, obj.get(s));
        }
    }

    public Packet(String op, Map<String, JsonElement> data) {
        this.op = op;
        this.data = data;
    }

    @Override
    public String toString() {
        return "Packet{" + "op='" + op + '\'' + ", data=" + data + '}';
    }

    public JsonObject toSerialized() {
        JsonObject jobj = new JsonObject();
        jobj.addProperty("op", op);
        if (data != null && !data.isEmpty()) {
            for (String s : data.keySet()) {
                jobj.add(s, data.get(s));
            }
        }
        return jobj;
    }
}
