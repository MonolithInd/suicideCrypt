# suicideCrypt
A tool for creating cryptographically strong volumes that destroy themselves upon tampering or via issued command. Included is a daemon designed to react to system events and on a configurable basis, destroy data volumes encrypted using the suicideCrypt tool. This process is fast and, if used correctly, both unrecoverable by an adversery and auditably unrecoverable by the volume owner. 

# Why suicideCrypt?
While looking at the options for self destroying encrypted data volumes it seemed that most of the work in the space involves custom engineered hard drives with hardware AES chips that self destruct based on a variety of triggers (hard drive removal, SMS, email, physical button etc). Almost universally these drives are epensive and, once triggered, unusable and have to be replaced at great cost. 

I wanted to see if I could duplicate the behavior of these drives in a safe, secure and non recoverable way using only open source software and known cryptographic best practises. In this way I hoped to bring secure, self destroying Hard Drives within the reach of the average Linux user. 

As a side goal I wanted to see if I could plausibly solve the ["rubber hose"](https://en.wikipedia.org/wiki/Rubber-hose_cryptanalysis) issue typical of cryptographic volumes as demonstrated by [this XKCD comic.](https://xkcd.com/538/). In the case of the commercial hardware products the AES key, whcih the user never has, is destroyed upon a trigger event. I wanted to see if it's possible to recreate this behavior upon server theft, or specific triggering events; intrusion, hardware loggers, hardware imagers etc.

In short, could I create a volume with an audit trail that proves to a reasonable level that the owner of the volume is personally unable to decrypt the volume once it is unmounted, tampered with or powered down. Turns out, yes.

# How?
suicideCrypt acheives the goal of strong cryptographic volumes that become unrecoverable upon tampering, even for the creator of the volume using 2 software components. 

* suicideCrypt : A tool for creating and destroying strong cryptographic volumes in such a manner that the creator, via audit trail, can claim zero ability to recover a destroyed cryptiographic volume. suicideCrypt can create secure block devices or, if required secure container files that can be mounted as a disk under linux/LUKS.

* suicideCryptd : A daemon that can be configured to monitor for various system events such as:
  * unauthorised logins 
  * remote destroy triggers 
  * hardware loggers
  * hardware imagers
  * other configurable events 

Then based on these, trigger destruction of suicideCrypt create drives on the local host. 

suicideCrypt volumes are created using the [Linux LUKS/dm-crypt modules](https://wiki.archlinux.org/index.php/Dm-crypt/Device_encryption) such that the key to decrypt the volume is not chosen or known by the admin of the system. suicideCrypt can create these volumes in one of two ways:

* Normal Mode: This volume can be unmounted and remounted as long as the server remains powered on, or the disk is undestroyed. There is also provision to copy the header and key to external or removable media so the drive can be recovered by the admin after a reboot. This highly limits resistence to "ruber hose" decryption.
* Paranoid Mode: In this mode the key and header used to encrypt the volume are deleted immediatly upon volume creation and mount. In this manner the drive is, auditably, fully unrecoverable in the event of unmount or power loss even to the creator of the drive. 

A full description of the LUKS/dm-crypt kenrnel module and how it works is beyond the scope of this readme. But simplified, the LUKS module uses a header attached to an encrypted device to store the cryptographic decryption key, and has a number of slots (8) to store keys that can be used to unlock the decryption key. In normal operation this header is prepended onto the start of the encrypted device/container and a passphrase or keyfile are used to lock/unlock the decrpytion key and mount the volume. 

suicideCrypt creates volumes where:

* The header component is physically seperated from the drive it unlocks.
* A fully random (for given values of random) 4096 bit keyfile is generated to lock/unlock the encryption key/header. 
* Both the header and random keyfile are stored on a temporary ramdisk in memory such that neither, in correct operation, are ever written to any kind of magnetic or SSD type media. 

By simply zeroing and unmounting the tmpfs ramdisk the ability to lock and unlock the encrypted volume are lost forever. suicideCrypt automates this process and makes it a simple single line command to create or destroy such volumes as well as mananging the tmpfs ramdisk required. 

In this manner, rapid and total destruction of the data volume is acheivable in seconds without requiring zeroing a large device. Furthermore all actions performed are logged in a full on disk audit log, showing that at no point did a typical operator have access to the cryptographic keys needed to lock/unlock the drive. The destruction of the header and keyfile, followed by an unmount is the software equivilent of destruction of the AES key in a hardware encryption drive. 

# Install

suicideCrypt is available as a .deb file downloaded from https://www.monolithindustries.com/repos/apt/debian/pool/main/s/suicidecrypt/ 

Or, if you like you can add the private GPG signed repository below by grabbing the public key with the command:: 

    wget -O - https://www.monolithindustries.com/repos/key/suicideCrypt.gpg.key|apt-key add -

Then adding the repository to your apt sources with::

    add-apt-repository "deb https://www.monolithindustries.com/repos/apt/debian xenial main"

Once this is done you should be able to do a simple::

    apt-get update
    apt-get install suicidecrypt

Otherwise you can git clone the software and move the various files into place manually. 

# Usage

suicidecrypt
------------

suicidecrypt is run from the command line and in abcense of any switches prints it's usage summary.::

    root@crypt-test:~# suicideCrypt

    sucicideCrypt version 1.0

    Usage:
    -n : create an encrypted volume in interactive mode
    -c <path> : Create a file container encrypted volume located on <path>, requires -s, -m, and optionally -p, -y
    -b <block device> : Create a block device encrypted volume, requires -b, -m, and optionally -p, -y
    -s <size>m/g : Size of encrypted container in meg or gig, used with -c
    -m <mountpoint> : Mountpoint for encrypted volume, used with -c and -b
    -l : List all suicideCrypt created volumes
    -d <volume, or leave blank for list> : Destroy an encrypted volume.
    -D : Destroy all detectable suicideCrypt volumes on this host.
    -u <volume, or leave blank for list> : Unmount an encrypted volume without destroying keyfile
    -U : unmount all detectable suicideCrypt volumes on this host.
    -i : Initialise a suicideCrypt ramdisk, place key and header files here before trying to re-attach a volume
    -a <container or block device to attach> : attach existing unmounted suicideCrypt drive, requires -m
    -p : default to paranoid mode in all volume creations.
    -r : Use /dev/random instead of /dev/urandom for all random number collection. WARNING, can significantly slow down volume creation
    -y : assume "yes" to all destroy/create confirmations. WARNING: You can delete a lot of data this way!
    -v : verbose, display more detail on execution.
    -h : Display this text.

    root@crypt-test:~#
In it's simplest mode suicidecrypt can be run with the "-n" options for "new" and it will prompt the user for the various options it requires to build a cryptographic volume. It will start off asking if you require a block or container type volume, select one. After that it simply reqires:

* A target block device (if you selected block device) e.g. /dev/sda
* A mount point to mount the drive (/mnt)
* A decision to create a normal or paranoid mode volume.

for a container type volume you will also be prompted for 

* Container size e.g 200m, 3g etc.
* Location to store the container file. *note* please make sure the target volume is large enough to hold the container you are making. 

The software will then display a summary of the choices you have made and ask if you wish to continue.::

    We are now ready to create your encrypted volume with the following options:

    #=====================================#
    | Type:                 Container     |
    | Container Location:   /root         |
    | Size:                 200M          |
    | Mount point:          /mnt          |
    | Source of entropy:    /dev/urandom  |
    | Keyfile:              4096 bytes    |
    | Hash spec:            sha512        |
    | Cipher:               aes256        |
    | Paranoid Mode:        no            |
    #=====================================#
 
    Do you wish to continue? (y/n):
Note that some of the options were not selectable during setup. These are "advanced" and can be changed via command line if required, some cannot. At the moment the keyfile size, Hash spec and cipher cannot be changed. This might be altered in a future version. 

