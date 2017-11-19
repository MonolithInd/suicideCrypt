# 1.0 suicideCrypt
A tool for creating cryptographically strong volumes that destroy themselves upon tampering or via issued command. Included is a daemon designed to react to system events and on a configurable basis, destroy data volumes encrypted using the suicideCrypt tool. This process is fast and, if used correctly, both unrecoverable by an adversary and auditably unrecoverable by the volume owner. 

# 2.0 Why suicideCrypt?
While looking at the options for self-destroying encrypted data volumes it seemed that most of the work in the space involves custom engineered hard drives with hardware AES chips that self-destruct based on a variety of triggers (hard drive removal, SMS, email, physical button etc). Almost universally these drives are expensive and some, once triggered, unusable and have to be replaced at great cost. 

I wanted to see if I could duplicate the behavior of these drives in a safe, secure and non-recoverable way using only open source software and known cryptographic best practices. In this way I hoped to bring secure, self destroying Hard Drives within the reach of the average Linux user. 

As a side goal I wanted to see if I could plausibly solve the ["rubber hose"](https://en.wikipedia.org/wiki/Rubber-hose_cryptanalysis) issue typical of cryptographic volumes as demonstrated by [this XKCD comic.](https://xkcd.com/538/). In the case of the commercial hardware products the AES key, which the user never has, is destroyed upon a trigger event. I wanted to see if it's possible to recreate this behavior upon server theft, or specific triggering events; intrusion, hardware loggers, hardware imagers etc.

In short, could I create a volume with an audit trail that proves to a reasonable level that the owner of the volume is personally unable to decrypt the volume once it is unmounted, tampered with or powered down. Turns out, yes.

# 3.0 How?
suicideCrypt achieves  the goal of strong cryptographic volumes that become unrecoverable upon tampering, even for the creator of the volume using 2 software components. 

* suicideCrypt : A tool for creating and destroying strong cryptographic volumes in such a manner that the creator, via audit trail, can claim zero ability to recover a destroyed cryptiographic volume. suicideCrypt can create secure block devices or, if required secure container files that can be mounted as a disk under linux/LUKS.

* suicideCryptd : A daemon that can be configured to monitor for various system events such as:
  * unauthorised logins 
  * remote destroy triggers 
  * hardware loggers
  * hardware imagers
  * other configurable events 

Then based on these, trigger destruction of suicideCrypt create drives on the local host. 

suicideCrypt volumes are created using the [Linux LUKS/dm-crypt modules](https://wiki.archlinux.org/index.php/Dm-crypt/Device_encryption) such that the key to decrypt the volume is not chosen or known by the admin of the system. suicideCrypt can create these volumes in one of two ways:

* Normal Mode: This volume can be unmounted and remounted as long as the server remains powered on, or the disk is undestroyed. There is also provision to copy the header and key to external or removable media so the drive can be recovered by the admin after a reboot. This highly limits resistance to "ruber hose" decryption.
* Paranoid Mode: In this mode the key and header used to encrypt the volume are deleted immediately upon volume creation and mount. All events of drive creation and key destruction are fully, high accuracy timestamp, logged to system logs. In this manner the drive is, auditably, fully unrecoverable in the event of unmount or power loss even to the creator of the drive. 

A full description of the LUKS/dm-crypt kenrnel module and how it works is beyond the scope of this readme. But simplified, the LUKS module uses a header attached to an encrypted device to store the cryptographic decryption key, and has a number of slots (8) to store keys that can be used to unlock the decryption key. In normal operation this header is prepended onto the start of the encrypted device/container and a passphrase or keyfile are used to lock/unlock the decrpytion key and mount the volume. 

suicideCrypt creates volumes where:

* The header component is physically separated from the drive it unlocks.
* A fully random (for given values of random) 4096 bit keyfile is generated to lock/unlock the encryption key/header. 
* Both the header and random keyfile are stored on a temporary ramdisk in memory such that neither, in correct operation, are ever written to any kind of magnetic or SSD type media. 

By simply zeroing and unmounting the tmpfs ramdisk the ability to lock and unlock the encrypted volume are lost forever. suicideCrypt automates this process and makes it a simple single line command to create or destroy such volumes as well as managing the tmpfs ramdisk required. 

In this manner, rapid and total destruction of the data volume is achievable in sub seconds without requiring zeroing a large device. Furthermore, all actions performed are logged in a full on disk audit log, showing that at no point did a typical operator have access to the cryptographic keys needed to lock/unlock the drive. The destruction of the header and keyfile, followed by an unmount is the software equivalent of destruction of the AES key in a hardware encryption drive. 

# 4.0 Install

suicideCrypt is available as a .deb file downloaded from https://www.monolithindustries.com/repos/apt/debian/pool/main/s/suicidecrypt/ for ubuntu 16 LTS and rasbian for raspberry pi.

Or, if you like you can add the private GPG signed repository below by grabbing the public key with the command:

    wget -O - https://www.monolithindustries.com/repos/key/suicideCrypt.gpg.key|apt-key add -

Then adding the repository to your apt sources with:

    add-apt-repository "deb https://www.monolithindustries.com/repos/apt/debian xenial main"

Once this is done you should be able to do a simple:

    apt-get update
    apt-get install suicidecrypt

Otherwise you can git clone the software and move the various files into place manually. 

# 5.0 Usage

5.1 suicidecrypt
------------

**5.1.1 Volume Creation:**

suicidecrypt is run from the command line and with -h or --help prints it's usage summary.:

    root@crypt-test:# suicideCrypt -h

    sucicideCrypt version 1.0

    Usage:

      -n : run program in interactive mode (default)

    Advanced Options:
    ----------------
    Create:
      -c <path> : Create an encrypted volume container located on <path>
      -b <block device> : Create an encrypted volume block device. e.g /dev/sdb
      -s <size>m/g : Size of encrypted container in meg or gig. e.g 200m or 4g
      -m <mountpoint> : Mountpoint to mount encrypted volume on e.g /mnt
    Manage:
      -l : List all suicideCrypt created volumes
      -d <volume, or leave blank for list> : Destroy an encrypted volume.
      -D : Destroy ALL detectable suicideCrypt volumes on this host.
      -u <volume, or leave blank for list> : Unmount an encrypted volume without destroying keyfile
      -U : unmount ALL detectable suicideCrypt volumes on this host.
      -i : Initialise a suicideCrypt ramdisk, used to remount an existing sucidecrypt volume
      -a <container or block device to attach> : remount an existing unmounted suicideCrypt drive.
      -p : default to paranoid mode in all volume creations. (see manpage for paranoid mode
      -r : Use /dev/random instead of /dev/urandom for all random number collection.
      -y : assume "yes" to all destroy/create confirmations.
      -v : verbose, display more detail on execution.
      -h : Display this text.

    root@crypt-test:# 

In it's simplest mode suicidecrypt can be run with the *"-n"* options for "new" and it will prompt the user for the various options it requires to build a cryptographic volume. It will start off asking if you require a block or container type volume, select one. After that it simply requires:

* A target block device (if you selected block device) e.g. /dev/sda
* A mount point to mount the drive (/mnt)
* A decision to create a normal or paranoid mode volume.

for a container type volume you will also be prompted for 

* Container size e.g 200m, 3g etc.
* Location to store the container file. *note* please make sure the target volume is large enough to hold the container you are making. e.g /usr/local/share/containers 

The software will then display a summary of the choices you have made and ask if you wish to continue:

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

If you wish the script the creation of a suicideCrypt device you can pre-enter all the options from the command line and skip the confirmation step using *"-y"*. 

For example, to create a cryptographic volume on /dev/sdb and mount it on /mnt you would enter the following:

    root@crypt-test:/# suicideCrypt -b /dev/sdb -m /mnt -y

This will create and mount your volume. 

To create a basic 2gig paranoid mode cryptographic container and mount it on /tmp/paranoid you would:

    root@crypt-test:/# suicideCrypt -c /usr/local/share/containers/ -m /tmp/paranoid -s 2g -p -y 

If you wish to see the steps of the creation process use "-v" for verbose.

**5.1.2 Volume Management**

You can quickly list all volumes currently created and mounted by suicide crypt using the *"-l"* option:

    root@crypt-test:/# suicideCrypt -l

    1: /dev/mapper/suicideCrypt_052219de-1863-43ed-9206-91f4ff4ff4a6 on /mnt
    2: /dev/mapper/suicideCrypt_f4eb961b-a19e-4b12-8440-4d5bd9257848 on /tmp/paranoid

    root@crypt-test:/# 

We can perform a variety of actions on these disks such as:

* -d destroy
* -D destroy all
* -u unmount
* -U unmount all

If you provide *"-d"* or *"-u"* with either the mapper path or the mount path as seen in the output of *"-l"* it will immediately destroy or unmount that volume. If you do not specify a volume it will show you the list and prompt you to select a drive from the list:

    root@crypt-test:/# suicideCrypt -d

    No volume specified, Please choose which mounted volume to destroy from this list:

    1: /dev/mapper/suicideCrypt_052219de-1863-43ed-9206-91f4ff4ff4a6 on /mnt
    2: /dev/mapper/suicideCrypt_f4eb961b-a19e-4b12-8440-4d5bd9257848 on /tmp/paranoid

    Enter number of volume you wish to destroy: 
    
***Please remember* that if you destroy a suicidecrypt container or block device is *cannot* be recovered via any method known to me. Be sure you wish to do this before selecting this option. **

If you chose to destroy a container based volume you will be prompted if you want to clean up the container file at the same time (it's now useless) you can call suicidecrypt with *"-y"* to automatically do this. 

Unmount performs similar actions to destroy in that it unmounts the volume mount and secure closes the cryptographic mapper interface, however it doesn't delete the LUKS header or keyfiles from the ramdisk /tmp/suicideCryptRAMdisk mount. If you have left these here the drive will be remountable until such time as the server is power cycled at which point **these files will be lost forever**.

If you wish to be able to remount a sucideCrypt disk past a power cycle the two files that match the UUID of the suicideCrypt device or container *must* be copied to some external media. **DO NOT** write these file to the spinning disk or SSD of the server itself. Doing so invalidates all security of the volumed in question. 

To remount a dismounted (not destroyed) suicideCrypt volume you can use the *"-a"* attach option. This requires 3 things:

* that the header file and keyfile for this volume are in /tmp/suicideCryptRAMdisk
* the container or volume you wish to remount.
* a mointpoint to mount the volume on.

Example:

    root@crypt-test:/# suicideCrypt -a /dev/sdb -m /mnt
    Sucessfully attached /dev/sdb on /mnt
    root@crypt-test:/# 

If you have moved the header and keyfile off the server and rebooted since it was mounted, you will need to create the initial ramdisk using *"-i"* and copy the correct header and keyfiles to this location for *"-a"* to work. Each header and keyfile is tagged with the UUID of the cryptographic volume. If you're not sure which key and header go with this volume you can get the UUID from the file or block device using:

    root@crypt-test:/# cryptsetup luksUUID /dev/sdb
    052219de-1863-43ed-9206-91f4ff4ff4a6
    root@crypt-test:/# 
    
5.2 suicideCryptd
-------------

This is the daemon to monitor and manage cryptographic volumes. It works best with volumes created by the suicideCrypt wrapper (automatic detection etc) but will work with any linux based cryptographic volumes with some configuration. 

If installed from .deb is can be started by using:

    service suicidecrypt start
    
This will start the daemon and begin watching for the default events. In it's base install suicidecryptd only monitors udev events and doesn't react beyond informational to any triggers. It will start, enumerate mounted suicidecrypt volumes and begin managing them. 

The main config file for suicidecryptd is:

    /etc/suicideCrypt/suicideCryptd.conf
    
The config is an apache style config. Built in monitors include:

* lmsensors
* udev events
* auth log parsing
* ossec IDS log parsing

These can all be turned on and off, and various trigger levels can be set for each of them. 

A default config file looks like: 

    defaultresponse = unmount
    unmountcmd = "/usr/local/bin/suicideCrypt.pl -y -u"
    destroycmd = "/usr/local/bin/suicideCrypt.pl -y -d"
    verbose = 1

    <mounts>
      <"/tmp/spam">
       defaultresponse = ignore  
       unmountcmd  = "/usr/local/bin/suicideCrypt.pl -y -d" 
      </"/tmp/spam">
    </mounts>

    <systemevents>
      <sensors>
        enabled = 0
        alerttemp = 15
        defaultresponse = destroy
      </sensors>

      <udevadm>
        enabled = 1
        <devices>
          keyboardmouse = 1
          monitor = 1
    #     disk = 1  # Disk is not supported yet.
          usb = 1 # USB will detect ANY usb state change. Use with caution. 
          network = 0
        </devices>
        defaultresponse = unmount
      </udevadm>
    </systemevents>

    <logs>
      <ossec>
        enabled = 0
        location = "/var/ossec/logs/alerts/alerts.log"
        paniclevel = 11
        defaultresponse = destroy
      </ossec>
      <auth>
        enabled = 1
        location = "/var/log/auth.log"
        defaultresponse = unmount
        allowedusers = ""
        ignorecron = 1
        allowsystemusers = 0
      </auth>
    </logs>

the default response can be either "ignore", "destroy", or "unmount". This value is set at the root of the config and can be changed at other points for differing responses depending on alert. The hierarchy is:

global < service < volume

So a service set default action will override the global, but if a particular volume is configured with a differing action to any default, that will always take precidence. 

In this way you can unmount by default; but if, for example, the system detects a RAM chill event and suspects someone is trying to extract your AES key, it can immediately destroy all drives by preference. 

5.2.1 Plugins
-------------
Suicidecryptd supports plugins to react to arbitrary external events. This can be used to trigger based on output from other IDS systems (tripwire etc) or from say, a post to a particular twitter feed. The receipt of a text message, phase of the moon or days ending in "y".

Plugins must reside in:

    /usr/local/share/suicidecrypt/plugins/
    
and are activated by making a sybolic link in: 

    /etc/sucidecrypt/plugins
    
Once the link is created, re-start the service and the new plugin will be active. 

Plugins can be any simple script that is called every 1 second. If there is no alarm the script must reply "OK" with no carriage return to console. 

If there is an alert it must print the name of the alert, the trigger level that caused the alert (arbitrary) and optionally a message to display in the log (or console in non-daemon mode) with the alert. eg, for the raspberryPi alert plugin:

    pi-temp;15;CPU temp 10 has dropped below 15
    
Please be careful with your suicideCryptd commands. If you are adding a new destroy check to the system first test it on a system with no important data. I wish to stress again that any volumes destroyed with suicidecryptd are **unrecoverable** and all data will be lost. 

# 6.0 Disclaimer

This script is provided "as is". I am in no way responsible if you use this script and it locks you out of your server on the other side of the planet, starts world war 3 or causes a global burrito shortage.

Written by Sebastian Kai Frost. sebastian.kai.frost@gmail.com



