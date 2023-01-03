package me.x150.discordqr;

import com.google.gson.JsonPrimitive;
import me.x150.discordqr.exc.UserCancelledException;
import me.x150.discordqr.exc.TimedOutException;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * An auth client for discord's QR code authorization system. The protocol is as follows:
 * <ol type="1">
 *     <li>Client generates a public and private RSA2048 key pair using the BouncyCastle algorithm</li>
 *     <li>Server sends "hello" packet, containing the heartbeat interval</li>
 *     <li>Client responds with "init" packet containing the base64 encoded public key</li>
 *     <li>Server responds with "nonce_proof" packet, containing random data encrypted with the public key</li>
 *     <li>Client responds with "nonce_proof" packet, containing the SHA256 hash of the decrypted data blob</li>
 *     <li>Server responds with "pending_remote_init", containing the ID of the created qr code session</li>
 *     <p>...</p>
 *     <li>User scans the QR code, server sends "pending_ticket", containing the encrypted user data of the client (without token). The user data consists of the username, discriminator, user ID and avatar ID</li>
 *     <li>If the user accepts, the server sends "pending_login", containing the <b>unencrypted</b> token of the user</li>
 *     <li>If the user declines, the server sends "cancel", and the connection is closed</li>
 * </ol>
 */
public class DiscordQrAuthClient {
    private static final URI WEBSOCKET_URI = URI.create("wss://remote-auth-gateway.discord.gg/?v=2");
    private final PacketWebsocket pws;
    private Thread intervalRunner;
    private final AtomicBoolean stop = new AtomicBoolean(false);
    private Cipher cipher;
    private KeyPair keys;
    private final Consumer<Throwable> error;
    private final CompletableFuture<String> tokenFuture = new CompletableFuture<>();
    private final CompletableFuture<String> codeFuture = new CompletableFuture<>();
    private final CompletableFuture<DiscordUser> codeScanned = new CompletableFuture<>();

    /**
     * Returns the future for the token
     * @return The future for the token
     */
    public CompletableFuture<String> getTokenFuture() {
        return tokenFuture;
    }

    /**
     * Returns the future for the fingerprint
     * @return The future for the fingerprint
     */
    public CompletableFuture<String> getCodeFuture() {
        return codeFuture;
    }

    /**
     * Returns the future for the target user
     * @return The future for the target user
     */
    public CompletableFuture<DiscordUser> getCodeScannedFuture() {
        return codeScanned;
    }

    /**
     * Initializes a new qr code authorization client
     * @param onError A callback, handling thrown exceptions
     * @throws Exception When key initialisation fails
     */
    public DiscordQrAuthClient(Consumer<Throwable> onError) throws Exception {
        this.error = onError;

        generateKeys();

        pws = new PacketWebsocket(WEBSOCKET_URI, Map.of("Origin", "https://discord.com"), this::handlePacket, integer -> {
            if (integer == 4003) {
                this.tokenFuture.completeExceptionally(new TimedOutException());
                try {
                    close();
                } catch (Throwable t) {
                    onError.accept(t);
                }
            }
        });
    }

    /**
     * Starts this qr code auth session, and connects to discord
     * @throws InterruptedException If the connection attempt is interrupted
     */
    public void start() throws InterruptedException {
        if (stop.get()) throw new IllegalStateException("Already closed");
        pws.connectBlocking();
    }

    private void generateKeys() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

        generator.initialize(2048, random);
        this.keys = generator.generateKeyPair();

        //Main.logDebug("Generated keys\n  Public: "+ Base64.encodeBytes(this.keys.getPublic().getEncoded())+"\n  Private: "+Base64.encodeBytes(this.keys.getPrivate().getEncoded()));
    }

    private byte[] decryptUsingKey(byte[] data) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, keys.getPrivate(), new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        return cipher.doFinal(data);
    }

    private String getPublicKey() {
        return encodeb64(keys.getPublic().getEncoded());
    }

    private byte[] toSha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String encodeb64(byte[] input) {
        return Base64.getEncoder().withoutPadding().encodeToString(input);
    }

    private void handlePacket(Packet packet) {
        System.out.println("IN "+packet);
        switch (packet.op) {
            case "hello" -> {
                long interv = packet.data.get("heartbeat_interval").getAsLong();
                intervalRunner = new Thread(() -> runInterval(interv));
                intervalRunner.setDaemon(true);
                intervalRunner.start();
                Packet p = new Packet("init", Map.of("encoded_public_key", new JsonPrimitive(getPublicKey())));
                pws.send(p.toSerialized().toString());
            }
            case "nonce_proof" -> {
                try {
                    String nonce = packet.data.get("encrypted_nonce").getAsString();
                    byte[] e = decryptUsingKey(Base64.getDecoder().decode(nonce));
                    byte[] proof = toSha256(e);
                    String j = Base64.getUrlEncoder().withoutPadding().encodeToString(proof);

                    Packet packet1 = new Packet("nonce_proof", Map.of("proof", new JsonPrimitive(j)));
                    pws.send(packet1.toSerialized().toString());
                } catch (Throwable e) {
                    error.accept(e);
                }
            }
            case "pending_remote_init" -> {
                codeFuture.complete(packet.data.get("fingerprint").getAsString());
            }
            case "pending_ticket" -> {
                try {
                    byte[] encUser = Base64.getDecoder().decode(packet.data.get("encrypted_user_payload").getAsString());
                    byte[] dec = decryptUsingKey(encUser);
                    String[] payload = new String(dec).split(":");
                    DiscordUser du = new DiscordUser(payload[0], payload[2], payload[3], Long.parseLong(payload[1])); // weird order but yes, this is correct
                    codeScanned.complete(du);
                } catch (Throwable e) {
                    error.accept(e);
                }
            }
            case "pending_login" -> {
                try {
                    String token = packet.data.get("ticket").getAsString();
                    this.tokenFuture.complete(token);
                    close();
                } catch (Throwable e) {
                    error.accept(e);
                }
            }
            case "cancel" -> {
                this.tokenFuture.completeExceptionally(new UserCancelledException());
                try {
                    close();
                } catch (Throwable e) {
                    error.accept(e);
                }
            }
        }
    }

    private void runInterval(long interval) {
        while (!stop.get()) {
            Packet p = new Packet("heartbeat", Map.of());
            pws.send(p.toSerialized().toString());

            try {
                Thread.sleep(interval);
            } catch (Exception ignored) {
                break;
            }
        }
    }

    private void close() {
        stop.set(true);
        pws.close();
        if (intervalRunner != null) {
            intervalRunner.interrupt();
        }
    }

    /**
     * A discord user
     * @param id The ID of the discord user
     * @param avatar The avatar ID of the discord user
     * @param username The username of the discord user
     * @param discriminator The discriminator of the discord user
     */
    public record DiscordUser(String id, String avatar, String username, long discriminator) {
        @Override
        public String toString() {
            return String.format("%s#%s (%s)", username, discriminator, id);
        }
    }
}
