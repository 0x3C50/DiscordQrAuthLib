# Discord QR authlib
An implementation of discord's QR code authorization protocol

## How does this work?
This library imitates to be a browser, contacting discord's websocket that manages the QR code login. The entire protocol is implemented, including the "preview" you see when you scan the QR code, but didn't accept it yet.

Note that this implementation **does not use discord's website to get the qr code**. It doesn't use, for example, selenium to get the QR code. Instead, the entire protocol is reimplemented in java. This makes it extremely efficient, as it doesn't have a whole web browser running in the background.

A deep dive into the protocol can be found in the javadoc in the `me.x150.discordr.DiscordQrAuthClient` class

## Installation
Just build the project using gradle, and get the compiled jarfile from `build/libs`

## Usage
An example can be found in the `me.x150.discordqr.Example` class.