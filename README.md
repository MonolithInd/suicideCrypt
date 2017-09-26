# suicideCrypt
A tool for creating cryptographically strong volumes that destroy themselves upon tampering or via issued command. Included is a daemon designed to react to system events and on a configurable basis, destroy data volumes encrypted using the suicideCrypt tool. This process is fast and, if used correctly, both unrecoverable by an adversery and auditably unrecoverable by the volume owner. 

# Why suicideCrypt?
While looking at the options for self destroying encrypted data volumes it seemed that most of the work in the space involves custom engineered hard drives with hardware AES chips that self destruct based on a variety of triggers (hard drive removal, SMS, email, physical button etc). Almost universally these drives are epensive and, once triggered, unusable and have to be replaced at great cost. 

I wanted to see if I could duplicate the behavior of these drives in a safe, secure and non recoverable way using only open source software and known cryptographic best practises. In this way I hoped to bring secure, self destroying Hard Drives within the reach of the average Linux user. 

As a side goal I wanted to see if I could plausibly solve the "rubber hose" issue typical of cryptographic volumes as demonstrated by [this XKCD comic.](https://xkcd.com/538/). In the case of the commercial hardware products the AES key, whcih the user never has, is destroyed upon a trigger event. I wanted to see if it's possible to recreate this behavior upon server theft, or specific triggering events; intrusion, hardware loggers, hardware imagers etc.

In short, could I create a volume with an audit trail that proves to a reasonable level that the owner of the volume is personally unable to decrypt the volume once it is unmounted, tampered with or powered down. Turns out, yes.
