package me.x150.discordqr;

import com.google.gson.JsonParser;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.util.Map;
import java.util.function.Consumer;

class PacketWebsocket extends WebSocketClient {
    Consumer<Packet> onPacket;
    Consumer<Integer> onClosed;

    public PacketWebsocket(URI uri, Map<String, String> headers, Consumer<Packet> onPacket, Consumer<Integer> onClosed) {
        super(uri, headers);
        this.onPacket = onPacket;
        this.onClosed = onClosed;
    }

    @Override
    public void onOpen(ServerHandshake handshakedata) {
    }

    @Override
    public void send(String text) {
        System.out.println("OUT " + text);
        super.send(text);
    }

    @Override
    public void onMessage(String message) {
        Packet packet = new Packet(JsonParser.parseString(message).getAsJsonObject());
        onPacket.accept(packet);
    }

    @Override
    public void onError(Exception ex) {
        ex.printStackTrace();
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        onClosed.accept(code);
    }
}
