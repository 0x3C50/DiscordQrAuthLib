package me.x150.discordqr;

public class Example {
    public static void main(String[] args) throws Exception {
        DiscordQrAuthClient discordAuth = new DiscordQrAuthClient(Throwable::printStackTrace);  // create the client, logging any errors
        discordAuth.getCodeFuture()
            .thenAccept(s -> System.out.println("Got QR code link: https://discordapp.com/ra/" + s));  // print the full url to stdout when we get it
        discordAuth.getCodeScannedFuture()
            .thenAccept(discordUser -> System.out.printf("User %s scanned qr code, waiting for confirmation%n", discordUser));  // print the user who scanned the qr code
        discordAuth.start();  // start the client
        String s1 = discordAuth.getTokenFuture().get();  // wait for the token to arrive
        System.out.println("OK: " + s1); // print the token
    }
}
