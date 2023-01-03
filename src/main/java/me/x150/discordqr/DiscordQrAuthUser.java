package me.x150.discordqr;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * An implementation of the mobile device (the "user"), who is using the authorization mechanism.
 */
public class DiscordQrAuthUser {
    private static final URI BASE_URI;
    private static final URI USERS_BASE_ENDPOINT, REMOTE_AUTH_SCAN, REMOTE_AUTH_FINISH;

    static {
        try {
            // https://discord.com:443/api/v9
            BASE_URI = new URI("https", null, "discord.com", 443, "/api/v9/", null, null);
            USERS_BASE_ENDPOINT = BASE_URI.resolve("users/@me"); // https://discord.com:443/api/v9/users/@me
            REMOTE_AUTH_SCAN = BASE_URI.resolve("users/@me/remote-auth"); // https://discord.com:443/api/v9/users/@me/remote-auth
            REMOTE_AUTH_FINISH = BASE_URI.resolve("users/@me/remote-auth/finish"); // https://discord.com:443/api/v9/users/@me/remote-auth/finish
        } catch (URISyntaxException e) {
            throw new RuntimeException("This should never have happened..?", e);
        }
    }

    private static final HttpClient CLIENT = HttpClient.newHttpClient();
    private static final Gson GSON = new Gson();
    private boolean didScan = false, didLogin = false;
    String token, fingerprint, hsToken;

    /**
     * Creates a new DiscordQrAuthUser
     * @param token The user token to use for logging into the qr code
     * @param fingerprint The fingerprint of the qr code's url
     * @param skipVerification Whether to skip token verification or not
     */
    public DiscordQrAuthUser(String token, String fingerprint, boolean skipVerification) {
        if (!skipVerification && !doVerify(token)) {
            throw new IllegalArgumentException("Token "+token+" is not valid");
        }
        this.token = token;
        this.fingerprint = fingerprint;
    }

    private HttpRequest.Builder setupReq(HttpRequest.Builder r) {
        return r.header("Authorization", this.token)
            .header("User-Agent", "cock dick balling/1.0");
    }

    /**
     * Sends the payload equivalent to first scanning the qr code. Will send basic user information to the qr code owner
     * @throws IOException When the web request fails
     * @throws InterruptedException When the web request fails
     */
    public void pretendScan() throws IOException, InterruptedException {
        if (didScan) throw new IllegalStateException("Double call to pretendScan()");
        JsonObject jo = new JsonObject();
        jo.addProperty("fingerprint", this.fingerprint);
        HttpRequest req = setupReq(HttpRequest.newBuilder(REMOTE_AUTH_SCAN))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(jo)))
            .build();
        HttpResponse<String> send = CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
        if (send.statusCode() == 404) throw new IllegalArgumentException("Remote authentication session expired or is invalid");
        String body = send.body();
        Structs.HandshakeResponse handshakeResponse = GSON.fromJson(body, Structs.HandshakeResponse.class);
        this.hsToken = handshakeResponse.handshakeToken;
        didScan = true;
    }

    /**
     * Actually logs into the qr code. It's recommended to wait about 2 seconds before calling login() after calling {@link #pretendScan()} if the target QR code is on discord.com/login itself, since the site isn't made to handle scanning the qr code that fast.
     * Will call {@link #pretendScan()}, if it hasn't already been called
     * @throws IOException When the web request fails
     * @throws InterruptedException When the web request fails
     */
    public void login() throws IOException, InterruptedException {
        if (didLogin) throw new IllegalStateException("Double call to login()");
        if (!didScan) {
            pretendScan();
        }

        if (this.hsToken == null) throw new IllegalStateException("Handshake token is null. This should never happen.");

        JsonObject jo = new JsonObject();
        jo.addProperty("handshake_token", this.hsToken);
        jo.addProperty("temporary_token", false);
        HttpRequest req = setupReq(HttpRequest.newBuilder(REMOTE_AUTH_FINISH))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(jo)))
            .build();
        CLIENT.send(req, HttpResponse.BodyHandlers.discarding());

        didLogin = true;
    }

    /**
     * Creates a new DiscordQrAuthUser with skipVerification set to false
     * @param token The user token to use for logging into the qr code
     * @param fingerprint The fingerprint of the qr code's url
     */
    public DiscordQrAuthUser(String token, String fingerprint) {
        this(token, fingerprint, false);
    }

    private static boolean doVerify(String token) {
        try {
            HttpRequest req = HttpRequest.newBuilder(USERS_BASE_ENDPOINT)
                .header("User-Agent", "cock dick balling/1.0")
                .header("Authorization", token)
                .build();
            HttpResponse<String> send = CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
            return send.statusCode() == 200; // token is only valid if we get an actual OK
        } catch (Throwable t) {
            return false;
        }
    }
}
