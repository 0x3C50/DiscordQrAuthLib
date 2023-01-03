package me.x150.discordqr;

import com.google.gson.annotations.SerializedName;

class Structs {
    public static class EncryptedTokenResponse {
        @SerializedName("encrypted_token")
        String encryptedToken;
    }
    public static class HandshakeResponse {
        @SerializedName("handshake_token")
        String handshakeToken;
    }
}
