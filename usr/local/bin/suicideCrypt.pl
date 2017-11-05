#!/usr/bin/perl -w

# suicideCrypt.pl : Creates plausibly intrusion and theft proof encrypted volumes
#                 : that can never be recovered, even by the creator once unmounted
#                 : or power is lost. 
# Author          : Sebastian Kai Frost
# Created On      : Monday 25th September 2017
# Status          : Released
# requirements    : At least 4 gig of RAM, and enough space on local volumes to 
#                 : hold any container of the size you wish to create. 
#		  : libjson-perl
# TODO            : * Add subs for enhanced audit logs, unmounting and remounting 
#                 : suicide crypt drives that aren't created in paranoid mode.
#                 : * allow user specified Cipher and keysize (other than 4096)
#                 : * check if block device has partitions before formatting
#                 : use /dev/random : dd if=/dev/random of=filename bs=1 count=512
#                 : filessytem sync afer wipes.
#From the aspect of actual security, LUKS with default parameters
#  should be as good as most things that are FIPS-140-2 certified,
#  although you may want to make sure to use /dev/random (by specifying
#  --use-random on luksFormat) as randomness source for the master key
#  to avoid being potentially insecure in an entropy-starved situation.



use strict;
use warnings;
use Time::HiRes qw(time);
use POSIX qw(strftime);
use Getopt::Long qw(:config no_ignore_case);
use Sys::Hostname;
use JSON;
use Data::Dumper;

### Editable Globals ###

my $DEBUG = 0;
my $VERBOSE = 0;
my $VERSION = "0.5";
my $HOST = hostname();
my $KEYSIZE = 512;
my $RAMDISK = "/tmp/suicideCryptRAMdisk";
my $LOGFILE = "/var/log/suicideCrypt.log";
my $LOG;
my %CMDOPTIONS = ();
my %USROPT;
my $uuID = "00000000-0000-0000-0000-000000000000";
# my $cryptID = randString();

### Begining of main program ###

parseOptions();

if (defined $CMDOPTIONS{v}) {
  $VERBOSE = 1; # set verbose 
}

# Choose what to execute.
if (defined $CMDOPTIONS{h}) {
  printHelp();
  exit(1);
} elsif (defined $CMDOPTIONS{n}) {
  logStart("Create");
  %USROPT = getOptions();
  new(%USROPT);
  logClose();
  exit(1);
} elsif (defined $CMDOPTIONS{b}) {
  logStart("Create");
  %USROPT = getOptionsCL();
  if (%USROPT) {
    new(%USROPT);
  }
  logClose();
  exit(1);
} elsif (defined $CMDOPTIONS{c}) { ## is this needed? 
  logStart("Create");
  %USROPT = getOptionsCL();
  if (%USROPT) {
    new(%USROPT);
  }
  logClose();
  exit(1);
} elsif (defined $CMDOPTIONS{l}) {
  listsuicideCryptVol();
  exit (1);
} elsif (defined $CMDOPTIONS{d}) {
  logStart("Destroy");
  destroy_unmount($CMDOPTIONS{d});
  logClose();
  exit (1);
} elsif (defined $CMDOPTIONS{D}) {
  logStart("DestroyAll");
  destroy_unmount_All();
  logClose();
  exit(1);
} elsif (defined $CMDOPTIONS{u}) {
  logStart("UnMount");
  destroy_unmount($CMDOPTIONS{d});
  logClose();
  exit (1);
} elsif (defined $CMDOPTIONS{U}) {
  logStart("UnMountAll");
  destroy_unmount_All();
  logClose();
  exit(1);
}

printHelp();

### Begin subs ###

### Parses all command line options and creates a global command hash
sub parseOptions {

  GetOptions ( \%CMDOPTIONS,
            "n|new",
            "c|container=s",
            "b|blockdevice=s",
            "s|size=s",
            "m|mountpoint=s",
            "l|list",
            "v|verbose",
            "d|destroy:s",
            "D|destroyall",
            "u|unmount",
            "U|unmountall",
            "p|paranoid",
            "r|random",
            "y|yes",
            "h|help")
  or die("Error in command line arguments\n");
}

### Create a suicideCrypt volume
sub new {

  my %usropt = @_;   
  my $cryptName;
  my $paranoid = $usropt{'paranoid'};
  my $volume;

  if ($paranoid) {
    $cryptName = "suicideCrypt-PARANOID";
  } else {
    $cryptName = "suicideCrypt";
  }
  print "\nWe are now ready to create your encrypted volume with the following options:\n\n";
  printOptions(%usropt); # show the user their choices for conformation before execution 
  print "\nDo you wish to continue? (y/n):";
  if (yN()) {
    if ($usropt{'type'} eq "c") {
      $volume = "$usropt{'location'}/$cryptName.img";
    } elsif ($usropt{'type'} eq "b") {
      $volume = "$usropt{'device'}";
    }
    printLC("\n-> Creating the requested volume...\n", 1);
    createTMPfs();
    createKeyFile();
    if ($usropt{'type'} eq "c") { 
      createContFile("$volume", "$usropt{'size'}$usropt{'unit'}");
    }
    setupCryptVol("$volume");
    # I now have a valid LUKS device, lets pull the UUID and use that 
    # as the unique identifier going forward.
    $uuID = getUUID($volume);
    $cryptName = $cryptName . "_$uuID";
#    renameUUID($volume, $uuID);
    if ($usropt{'type'} eq "c") {
      renameUUID($volume, $uuID);
      $volume = "$usropt{'location'}/$cryptName.img";
    }
    renameUUID("$RAMDISK/keyfile", $uuID);
    # If running paranoid mode, delete the header and key, otherwise copy the header to the 
    # ramdisk in case the user wishes to remount later.
    if ($paranoid) {
      unlockCryptVol("$cryptName", "$volume", $paranoid); 
      luksEraseHdr("$volume");
      enableParanoid($uuID);
    } else {
      backupLuksHdr("$volume");
      luksEraseHdr("$volume"); 
      unlockCryptVol("$cryptName", "$volume", $paranoid);
    }
    formatCryptVol("$cryptName");
    mountCryptVol("$cryptName", "$usropt{'mountpoint'}");

    printLC("-> Success, volume is now mounted on $usropt{'mountpoint'}\n", 1);
  } else { 
    printLC("-> Aborting create...\n", 1);
  }
} 

sub renameUUID {
  my $file = shift;
  my $newID = shift;
  my $newfile;
  my $temp;

  if ($file =~ /img/) { 
    $temp = (split(/\./, $file))[0];
    $newfile = $temp . "_" . $newID . ".img";
  } else { 
    $newfile = "$file" . "_" . "$newID";
  }

  rename("$file", "$newfile");

}

# Collect and parse the Command line options
sub getOptionsCL {

  my %options;

  if ($CMDOPTIONS{b}) {
    $options{'type'} = "b";
    unless (defined $CMDOPTIONS{m}) {
      print "-b requires that -m also be set\n";
      printLC("-> Invalid command line options, aborting\n");
      %options = ();
      return(%options);
    }
    unless (-e $CMDOPTIONS{b}) {
      print "\n** $CMDOPTIONS{b} is not a valid block device! Please re-enter a valid device **\n\n";
      %options = ();
      return(%options);
    }
    $options{'device'} = $CMDOPTIONS{b};
    if (defined($CMDOPTIONS{p})) {
      $options{'paranoid'} = 1;
    }
  } elsif ($CMDOPTIONS{c}) {
    $options{'type'} = "c";
    unless ((defined $CMDOPTIONS{s}) && (defined $CMDOPTIONS{m})) {
      print "-c requires that -s and -m also be set\n";
      printLC("-> Invalid command line options, aborting\n");
      %options = ();
      return(%options); 
    }
    unless (-d $CMDOPTIONS{c}) {
      print "\n**  You have specified an invalid location for the container file **\n\n";
      printLC("-> Invalid command line options, aborting\n");
      %options = (); 
      return(%options);
    }
    $options{'location'} = $CMDOPTIONS{c};
    ($options{'size'}, $options{'unit'}) = isValidUnit($CMDOPTIONS{s});
    unless ($options{'size'}) {
      print "\n**  You have specified an invalid unit for the container size **\n\n";
      printLC("-> Invalid command line options, aborting\n");
      %options = (); 
      return(%options);
    }
  }
  unless ((-d $CMDOPTIONS{m}) && is_folder_empty($CMDOPTIONS{m}) ) {  
    print "\n** Specified mountpoint is not emptry or doesn't exist ** \n\n";
    printLC("-> Invalid command line options, aborting\n");
    %options = ();
    return(%options);
  }
  $options{'mountpoint'} = $CMDOPTIONS{m};
  return(%options);
}

### zero and delete a LUKs/suicideCrypt keyfile. 
sub removeKey {
	
  my $id = shift;

  printLC("    -> Zeroing keyfile $RAMDISK/keyfile_$id ...\n", $VERBOSE);
  zeroFile("$RAMDISK/keyfile_$id"); ## Lets overwrite it with Zeros before we unlink it. potential ram freezing.
  sleep 0.5; # Lets sleep for a half second to make sure it writes to ram. Possibly no needed. To review.
  printLC("    -> Done Zeroing keyfile $RAMDISK/keyfile_$id.\n", $VERBOSE);
  printLC("    -> Unlinking keyfile $RAMDISK/keyfile_$id ...\n", $VERBOSE);
  unlink("$RAMDISK/keyfile_$id");
  printLC("    -> Done unlinking LUKS keyfile $RAMDISK/keyfile_$id.\n", $VERBOSE);
  if (is_folder_empty($RAMDISK)) {
    printLC("     -> RAMDISK is empty, no more volumes, unmounting and deleting $RAMDISK\n", $VERBOSE);
    system("umount $RAMDISK");
    rmdir($RAMDISK);
    printLC("    -> Done unmounting and deleting $RAMDISK\n", $VERBOSE);
  }
}

sub removeHdr {

  my $id = shift; 

  printLC("    -> Zeroing LUKS header file $RAMDISK/hdrfile_$id ...\n", $VERBOSE);   
  zeroFile("$RAMDISK/hdrfile_$id"); ## Lets overwrite it with Zeros before we unlink it. potential ram freezing.
  sleep 0.5; # Lets sleep for a half second to make sure it writes to ram. Possibly no needed. To review. 
  printLC("    -> Done Zeroing header file $RAMDISK/hdrfile_$id .\n", $VERBOSE); 
  printLC("    -> Unlinking header file $RAMDISK/hdrfile_$id ...\n", $VERBOSE);
  unlink("$RAMDISK/hdrfile_$id");
  printLC("    -> Done unlinking LUKS header $RAMDISK/hdrfile_$id.\n", $VERBOSE);
  if (is_folder_empty($RAMDISK)) {
    printLC("    -> RAMDISK is empty, no more volumes, unmounting and deleting $RAMDISK\n", $VERBOSE);
    system("umount $RAMDISK");
    rmdir($RAMDISK);
    printLC("    -> Done unmounting and deleting $RAMDISK\n", $VERBOSE);
  } 
}


### destroy a suicideCrypt volume, can take a mount point, mapper refrence,
### or if nothing given lets the user select from a list.
sub destroy_unmount {

  my $volume = shift;
  my $select;
  my %allVols = getMounted();
  my $valid = 0;
  my @volNum = keys(%allVols);
  my $val;
  my @destroyunmountVol;
  my $action;

  if ($CMDOPTIONS{d} || $CMDOPTIONS{D}) {
    $action = "destroy";
  } elsif ($CMDOPTIONS{u} || $CMDOPTIONS{U}) {
    $action = "unmount";
  }
  if (!@volNum) {
    printLC("\n-> No suicideCrypt volumes detected mounted on this host, doing nothing\n\n", 1);
    return (0);
  }
  if (!$volume) {
    print "\nNo volume specified, Please choose which mounted volume to $action from this list:\n";
    
    listsuicideCryptVol();
    while (!$valid) {
      print "Enter number of volume you wish to $action: ";
      $select = <STDIN>;
      chomp($select);
      foreach $val (@volNum) {
        if ($select =~ m/$val/) {
          $valid = 1;
        } 
      }
      if ($valid) {
        push @destroyunmountVol, $select;
        destroy_unmount_Volumes(@destroyunmountVol);
      } else {
        print "Invalid selection, please select an existing volume from the list\n"; 
      }
    }
  } else {
    foreach $val (@volNum) {
      if (($volume =~ $allVols{$val}{'mapper'}) || ($volume =~ $allVols{$val}{'mountpoint'})) {
        push @destroyunmountVol, $val;
        destroy_unmount_Volumes(@destroyunmountVol);
        exit(1);
      }
    }
    print "\nYou have not specified a valid mounted suicideCrypt mapper refrence or mountpoint\n\n";
  }  
}

### Destroy all suicideCrypt drives that the script can detect. If you've unmounted a drive manually
### then you may be screwed as this will not detect the drive and as such not delete and key or 
### header files in ramdisk. Don't do that. 
sub destroy_unmount_All {

  my %allVols = getMounted();
  my @volNum = keys(%allVols);  
  my $action;

  if ($CMDOPTIONS{d} || $CMDOPTIONS{D}) {
    $action = "destroy";
  } elsif ($CMDOPTIONS{u} || $CMDOPTIONS{U}) {
    $action = "unmount";
  }

  if (!@volNum) {
    printLC ("\n-> No suicideCrypt volumes detected mounted on this host, doing nothing\n\n", 1);
    return (0);
    exit(1);
  } 
  print "\nYou have chosen to $action ALL detectable mounted suicideCrypt volumes on this host!\n";
  $action = $action . "ing";
  if (yes()) {
    printLC("\n-> $action all detectable mounted suicideCrypt volumes\n", 1);
    destroy_unmount_Volumes(@volNum);
    printLC("-> Done $action all volumes\n", 1);
  } else { 
    printLC("-> Aborted!\n", 1);
  }

}

### Sub that actually takes a list of volumes and deletes them.
sub destroy_unmount_Volumes {

  my @destroyunmountVols = @_;
  my %allVols = getMounted();
  my $vol;
  my @temp;
  my $mapper;
  my $id;
  my $deleteable = 0;
  my $action;

  if ($CMDOPTIONS{d} || $CMDOPTIONS{D}) {
    $action = "destroying";
  } elsif ($CMDOPTIONS{u} || $CMDOPTIONS{U}) {
    $action = "unmounting";
  }

  foreach $vol (@destroyunmountVols) {
    $mapper = $allVols{$vol}{'mapper'};
    @temp = split('_', $mapper);
    $id = $temp[1];
    if ($CMDOPTIONS{d} || $CMDOPTIONS{D}) {
      printLC("-> Destroying sucideCrypt volume $mapper\n", $VERBOSE);
      # Lets get rid of the key and header file (if they exist) first, the faster
      # we get rid of these the faster the volume is destroyed.
      if (!($mapper =~ m/PARANOID/)) {
        printLC("  -> Deleting keyfiles and header files from $RAMDISK\n", $VERBOSE);
        removeKey($id);
        removeHdr($id);
      } else {
        printLC("  -> Paranoid mode volume, no headers or keyfiles to delete\n", $VERBOSE);
      }
      # Lets wipe the on disk header again, just in case it wasn't done during creation.
      luksEraseHdr($allVols{$vol}{'blkdev'});
      # Grab the file location before we unmount it and can't get that info anymore.
      if ($allVols{$vol}{'blkdev'} =~ /loop/) {
        $deleteable = getContainer($allVols{$vol}{'blkdev'});
      }
    }
    printLC("  -> Umounting $allVols{$vol}{'mountpoint'}\n", $VERBOSE);
    system ("umount $mapper");
    printLC("  -> Done unmounting $mapper.\n", $VERBOSE);
    printLC("  -> Closing LUKS Crypt volume $mapper\n", $VERBOSE);
    system("cryptsetup close $mapper");
    printLC("  -> Done closing LUKS Volume $mapper\n", $VERBOSE);
    if ($CMDOPTIONS{d} || $CMDOPTIONS{D}) {
      if ($deleteable) {
        if ($CMDOPTIONS{y}) {
          deleteCont($deleteable);
        } else {
          print "  -> This volume was a mounted container, do you want to delete the container file? (y/n):";
          if (yN()) {
            deleteCont($deleteable);
          }
        }
        $deleteable = 0;
      }
    }
    printLC("  -> Done $action suicideCrypt volume\n", $VERBOSE);
    if ($CMDOPTIONS{d} || $CMDOPTIONS{D}) {
      printLC("-> SuicideCrypt volume $mapper is destroyed and unrecoverable\n", 1);
    }
  }
}

sub yN {

  my $input;
  my $valid = 0;

  if ($CMDOPTIONS{y}) {
    print "\n";
    return 1;
  }

  while (!$valid) {
    $input = <STDIN>;
    chomp($input);
    if ($input eq "y") {
      return (1);
      $valid = 1;
    } elsif ($input eq "n") {
      return (0);
      $valid = 1;
    } else {
      print "Invalid selection, please try again (y/n):";
    }
  }
}

sub getContainer {
  my $loop = shift;
  my $result;
  my @temp;
  my $line;
  my $container;

  $result = `losetup --list`;
  @temp = split /\n/, $result;
  foreach $line (@temp) {
    if ($line =~ $loop) {
      @temp = ();
      @temp = split (' ', $line); 
      $container = $temp[5];
      last;
    }
  }
  return $container;
}

sub deleteCont {
  
  my $container = shift;

  # TODO make sure tbis worked. 
  printLC("  -> Deleting on disk container $container\n", $VERBOSE);
  unlink($container);
  printLC("  -> Done deleting container file\n", $VERBOSE);
  return (1);

}

sub luksEraseHdr {

  my $device = shift;
  my $luksEraseCmd = "cryptsetup luksErase --batch-mode $device >/dev/null 2>&1";
  
  printLC("  -> Wiping keys from on disk header...\n", $VERBOSE);
  system($luksEraseCmd);
  system("sync");
  printLC("  -> Done erasing on disk LUKS header keys\n", $VERBOSE);
  return 1;
}


### list all mounted suicideCrypt volumes. 
sub listsuicideCryptVol {

  my %volumes;
  my $key;

  %volumes = getMounted();

  if (!%volumes) {
    print "\nNo mounted suicideCrypt Volumes found\n\n";
  } else {
    print "\n";
    foreach $key (sort(keys %volumes)) {
      print "$key: $volumes{$key}{'mapper'} on $volumes{$key}{'mountpoint'}\n";
   
    }
    print "\n";
  }

}

### Get a list of all mounted suicideCrypt volumes. Finds them using lsblk
### so if you manually unmount the drive we will not find them. 
sub getMounted {

  my $devCmdJ = "lsblk -J -s -p";
  my $cmdOutput;
  my $dev;
  my $volume;
  my $child;
  my $count = 1; 
  my %vols;

  $cmdOutput = `$devCmdJ`;

  $dev = from_json($cmdOutput, {utf8 => 1});

  foreach my $volume (@{ $dev->{'blockdevices'} }) {
    if ($volume->{name} =~ "suicideCrypt") {
      $vols{$count}{'mapper'} = $volume->{name};
      $vols{$count}{'mountpoint'} = $volume->{mountpoint};
      foreach my $child (@{ $volume->{'children'} }) {
        $vols{$count}{'blkdev'} = $child->{name}
      }
      $count++;
    }
  }
  return %vols;
}

### Create an randomised X byte keyfile to encrypt the volumes with important for suicideCrypt as 
### the user never knows the content of this key. Once it is deleted in the audit trail. The user 
### no longer has the ability to decrypt this volume. We use /dev/urandom here. But for true 
### cryptographic strength the user should use a source of true random data such as a hardware
### random number generator as a mid-option. -r enables use of /dev/random. Can be slow
sub createKeyFile {

  
  my $cmd; 
  if ($CMDOPTIONS{r}) {
    $cmd = "dd if=/dev/random of=$RAMDISK/keyfile bs=1 count=$KEYSIZE >/dev/null 2>&1";
  } else {
    $cmd = "dd if=/dev/urandom of=$RAMDISK/keyfile bs=1 count=$KEYSIZE >/dev/null 2>&1";
  }
  printLC("  -> Creating the random $KEYSIZE byte keyfile for the volume: $RAMDISK/keyfile\n", $VERBOSE);
  system ($cmd);
  printLC("  -> Success creating keyfile\n", $VERBOSE);
  return (1);

}

### simple yes/no call.
sub yes {

  my $selection;
  my $valid;

  if ($CMDOPTIONS{y}) {
    return 1;
  }
  print "Are you sure you wish you do this? Type YES in capitals to continue (any other key to abort): ";
  $selection = <STDIN>;
  chomp($selection);
  if ($selection eq "YES") {
    return 1;
  } else { 
    return 0;
  }  
}

### print out the options the user chose when prompted before execution. 
sub printOptions {
  
  my (%options) = @_;
  my $type = $options{'type'};
  my $size;
  my $location;
  my $unit;
  my $paranoid = $options{'paranoid'};
  my $mountpoint = $options{'mountpoint'};
  my $device;


    print "#=====================================#\n";
  if ($type eq "c") {
    $location = $options{'location'};
    $size = $options{'size'} . $options{'unit'};
    print "| Type:                 Container     |\n";
    printf "| Container Location:   %-14s|\n", $location;
    printf "| Size:                 %-14s|\n", $size;
  } elsif ($type eq "b") {
    $device = $options{'device'};
    print "| Type:                 Block Device  |\n";
    printf "| Block Device:         %-14s|\n", $device;
  }
  printf "| Mount point:          %-14s|\n", $mountpoint;
  print "| Source of entropy:    ";
  if ($CMDOPTIONS{r}) { 
    print "/dev/random   |\n";
  } else { 
    print "/dev/urandom  |\n";
  } 
  print "| Keyfile:              $KEYSIZE bytes     |\n";
  print "| Hash spec:            sha512        |\n";
  print "| Cipher:               aes256        |\n";
  print "| Paranoid Mode:        ";
  if ($paranoid) {
    print "yes           |\n";
  } else { 
    print "no            |\n";
  }
    print "#=====================================#\n"; 
}

sub createTMPfs {

  # Here we create the ramdisk for the storage of the hdr and key files
  # NB: We use a ramfs instead of a tmpfs because ramfs doesn't write to swap
  # if memory fills up. However if you keep writing to the ramdisk then you 
  # can fill up ram and crash the system. Don't use the SC ramdisk for other
  # things. You can change this to a tmpfs disk below if you like. but be aware
  # that this could severly decrease the security of your disks. 
# my $cmd = "mount -t tmpfs -o size=512m tmpfs $RAMDISK";
  my $cmd = "mount ramfs $RAMDISK -t ramfs";
  my $fh;
  my $line;
  my $found = 0;

  # Lets check if there is a suicideCrypt ramdisk already mounted.
  open ($fh, '<', "/proc/mounts");
  while ($line = <$fh>) {
    if ($line =~ "suicideCryptRAMdisk") {
      $found = 1;
    } else {
      #do nothing
    }
  }
  close $fh;
  if ($found) {
    printLC("    -> Found exisitng mounted suicideCrypt ramdisk, assuming exisitng suicideCrypt devices and continuing...\n", $VERBOSE);
    return (1);
  }
  # Otherwise lets make one...
  printLC("  -> Creating ramdisk for LUKS header and keyfile...\n", $VERBOSE);
  if (-d $RAMDISK) {
    # Dir already exists (perhaps bad delete previosly? Stale? Either way, use it)
    printLC("    -> $RAMDISK already exisits, assuming previous suicideCrypt use on running system and continuing...\n", $VERBOSE);
  } else { 
    printLC("    -> creating ram disk mount point: $RAMDISK\n", $VERBOSE); 
    unless(mkdir $RAMDISK) {
      die "Unable to create ram disk : $RAMDISK\n";
    }
    printLC("    -> Success creating ramdisk mount point\n", $VERBOSE);
  }

  printLC("    -> Mounting ramdisk on $RAMDISK.\n", $VERBOSE);
  system($cmd);
  printLC("    -> Success mounting ramdisk\n", $VERBOSE);
  printLC("  -> Ramdisk creation Success.\n", $VERBOSE);
}

sub createContFile {
  my $filename = shift;
  my $size = shift;
  my $containerCmd = "dd if=/dev/zero of=$filename bs=1 count=0 seek=$size >/dev/null 2>&1";

  printLC("  -> Creating blank container file for LUKS...\n", $VERBOSE);
  system($containerCmd);
  if (-e "$filename") {
    printLC("  -> Success creating blank container\n", $VERBOSE);
    return (1);
  } else { 
    printLC("  -> Failed to create blank container file! Please check permissions\n", 1);
    printLC("  -> Cleaning up created header...\n", 1);
    removeKey($uuID);
    printLC("-> Creating the requested volume FAILED!\n", 1);
    exit(0);
  }
}

sub setupCryptVol {
  my $volume = shift;
  my $keyfile = "$RAMDISK/keyfile";
  my $cryptSetupCmd;

  if ($CMDOPTIONS{r}) {
    $cryptSetupCmd = "cryptsetup luksFormat -s 512 --hash sha512 --use-random --batch-mode $volume $keyfile";
  } else {
    $cryptSetupCmd = "cryptsetup luksFormat -s 512 --hash sha512 --batch-mode $volume $keyfile";
  }
  printLC("  -> Using Cryptsetup to encrypt container file...\n", $VERBOSE);
  system($cryptSetupCmd);
  #TODO check this worked. 
  printLC("  -> Success encrypting container\n", $VERBOSE);
  return (1);
}

sub enableParanoid {
  my $id = shift;

  printLC("  -> Paranoid mode selected, Erasing all keys from header and deleting LUKS keyfile.\n", 1);
  printLC("  -> !! After this point, volume will be unrecoverable after reboot/unmount/destroy !!\n", 1);
  removeKey($id);
  return(1);
}

sub backupLuksHdr {
  my $volume = shift;
  my $hdrfile = "$RAMDISK/hdrfile_$uuID";
  my $cryptHdrBackupCmd = "cryptsetup luksHeaderBackup $volume --header-backup-file $hdrfile";

  printLC("  -> Backing up LUKS header to ramdisk...\n", $VERBOSE);
  system($cryptHdrBackupCmd);
  # TODO check the file was made!
  printLC("  -> Success Backing up LUKS header.\n", $VERBOSE);
  return (1);
}

sub unlockCryptVol {
  my $cryptName = shift;
  my $filename = shift;
  my $paranoid = shift;
  my $cryptOpenCmd;
  if ($paranoid) {
    $cryptOpenCmd = "cryptsetup luksOpen $filename $cryptName --key-file $RAMDISK/keyfile_$uuID";
  } else {
    $cryptOpenCmd = "cryptsetup luksOpen $filename $cryptName --key-file $RAMDISK/keyfile_$uuID --header=$RAMDISK/hdrfile_$uuID";
  }

  printLC("  -> Opening the Encrypted container and creating /dev/mapper link...\n", $VERBOSE);
  system ($cryptOpenCmd);
  # TODO make sure this worked
  printLC("  -> Success creating /dev/mapper/$cryptName\n", $VERBOSE);
  return(1);
}

sub formatCryptVol {
  my $cryptFileName = shift;
  my $cryptFmtCmd  = "mkfs.ext4 /dev/mapper/$cryptFileName >/dev/null 2>&1";

  printLC("  -> Formatting the unencrypted container EXT4, this may take a while depending on container size...\n", $VERBOSE);
  system($cryptFmtCmd);
  printLC("  -> Success formatting container\n", $VERBOSE);
  return (1);
}

sub mountCryptVol  {
  my $cryptFileName = shift;
  my $mountPoint = shift;
  my $mntCmd = "mount /dev/mapper/$cryptFileName $mountPoint";

  printLC("  -> Mounting your encrypted container on $mountPoint...\n", $VERBOSE);
  system($mntCmd);
  printLC("  -> Success mounting container\n", $VERBOSE);
  return (1);
}

sub getOptions {
  my %options;

  print "\n*** Welcome to suicideCrypt $VERSION.*** \n\n";
  print "First we need to gather a few details about the volume you wish to create;\n\n";
 
  $options{'type'} = getType();
  if ($options{'type'} eq "c") {
    ($options{'size'}, $options{'unit'}) = getSize();
    $options{'location'} = getLocation();
  } elsif ($options{'type'} eq "b") {
    $options{'device'} = getDevice();
  }
  $options{'mountpoint'} = mountPoint();
  $options{'paranoid'} = getParanoid();

  return %options;
}

sub getParanoid {
  
  my $paranoid;
  my $selection;
  my $valid = 0;

  if ($CMDOPTIONS{p}) {
    $paranoid = 1;
    return $paranoid;
  }
  while (!$valid) {
    print "\n - [Paranoid Mode] -\n\n";
    print "  - Create this PARANOID suicideCrypt volume (y/n/?): ";
    $selection = <STDIN>;
    chomp $selection;
    if ($selection eq "y") {
      $paranoid = 1;
      $valid = 1;
    } elsif ($selection eq "n") {
      $paranoid = 0;
      $valid = 1;
    } elsif ($selection eq "?") {
      print "\n\n** Blah Blah on pranoid mode! ** \n\n";
    } else {
      print "** You have entered an invalid option, please try again **\n\n";
    }
  }
  return $paranoid;
}

sub mountPoint { 

  my $selection;
  my $valid = 0;
   my $mp = "";

  while (!$valid) {
    print "\n - [Mount Point] -\n\n";
    print "  - Enter the path the mount point for this volume e.g /mnt:  ";
    $selection = <STDIN>;
    chomp $selection;
    if ((-d $selection) && is_folder_empty($selection) ) {
      $mp = $selection;
      $valid = 1;
    } else { 
      print "\n**  You have enterd an invlaid mount point, either the directory doesn't exist or isn't empty. Please try again **\n\n";
    }
  }
  return $mp;
}


sub getDevice {

  my $selection;
  my $valid = 0;
  my $device = "";

  while (!$valid) {
    print "\n - [Block device to encrypt] -\n\n";
    print "  - Enter path of the block device ie. /dev/sdb, /dev/sdc1: ";
    $selection = <STDIN>;
    chomp $selection;
    if (-e $selection) {
      $device = $selection;
      $valid = 1;
    } else { 
     print "\n** $selection is not a valid block device! Please re-enter a valid device **\n\n";
    }
  }
  return $device;
}

sub getLocation {

  my $selection;
  my $valid = 0;
  my $location = "";
  

  while (!$valid) {
    print "\n - [Location to save encrypted container] -\n\n";
    print "  - Path to save encrypted container file: ";
    $selection = <STDIN>;
    chomp $selection;
    if (-d $selection) {
      $location = $selection;
      $valid = 1;
    } else {
      print "\n** This is not a valid location. Please enter a valid location on the local filesystem ** \n";
    }
  }
  return $location;
}

sub getSize {
  my $selection;
  my $valid = 0;
  my $size;
  my $unit;

  while (!$valid) {
    print "\n - [Size of the encrypted container] -\n\n";
    print "  - Size of the container in megabytes or gigabytes (e.g, 500m or 5g):";
    $selection = <STDIN>;
    chomp($selection);
    ($size, $unit) = isValidUnit($selection);
    if ($size) {
      $valid = 1;
    } else {
      print "\n** Invalid unit or size, please try again ** \n";
    }
  }
  return($size, $unit);
}

sub isValidUnit {

  my $size = shift;
  my $unit;

  $unit = chop($size);
  $unit = uc ($unit);
  if (($unit eq "G") || ($unit eq "M")) {
    return($size, $unit);
  } else {
    return(0,0);
  }
}

sub getType {

  my $selection;
  my $valid = 0;
  my $type;

  while (!$valid) {
    print " - [Volume Type] -\n\n";
    print "  - Create an encrypted (c)ontainer file? Or an encypted (b)lock device? (c/b): ";
    $selection = <STDIN>;
    chomp($selection);
    if ($selection eq "c") {
      $type = "c";
      $valid = 1;
    } elsif ($selection eq "b") {
      $type = "b";
      $valid = 1;
    } else {
      print "\n** Invalid selection ** \n\n";
    }
  }
  return $type;
}

# Generates a random 16 digit string to concatonate to the name of a suicideCrypt volume to prevent collision of multiple volumes.
#sub randString {
#
#  my @chars;
#  my $string;
#
# @chars = ("A".."Z", "a".."z", "0".."9");
#  $string .= $chars[rand @chars] for 1..16;
#  return $string;
#}

sub is_folder_empty {
  my $dirname = shift;

  opendir(my $dh, $dirname) or die "Not a directory";
  return scalar(grep { $_ ne "." && $_ ne ".." } readdir($dh)) == 0;

}

sub zeroFile {

  my $filename =  shift;
  my $size;
  my $cmd;  

  $size = -s $filename;

  $cmd = "dd if=/dev/zero of=$filename bs=$size count=1 >/dev/null 2>&1";
  system($cmd);
  return (1);

}

sub printHelp {

  printVer();
  print "Usage:\n";
  print "-n : create an encrypted volume in interactive mode\n";
  print "-c <path> : Create a file container encrypted volume located on <path>, requires -s, -m, and optionally -p, -y\n";
  print "-b <block device> : Create a block device encrypted volume, requires -b, -m, and optionally -p, -y\n";
  print "-s <size>m/g : Size of encrypted container in meg or gig, used with -c\n";
  print "-m <mountpoint> : Mountpoint for encrypted volume, used with -c and -b\n";
  print "-l : List all suicideCrypt created volumes\n";
  print "-d <volume, or leave blank for list> : Destroy an encrypted volume.\n";
  print "-D : Destroy all detectable suicideCrypt volumes on this host.\n";
  print "-u <volume, or leave blank for list> : Unmount an encrypted volume without destroying keyfile\n";
  print "-U : unmount all detectable suicideCrypt volumes on this host.\n";
  print "-p : default to paranoid mode in all volume creations.\n";
  print "-r : Use /dev/random instead of /dev/urandom for all random number collection. WARNING, can significantly slow down volume creation\n";
  print "-y : assume \"yes\" to all destroy/create confirmations. WARNING: You can delete a lot of data this way!\n";
  print "-v : verbose, display more detail on execution.\n";
  print "-h : Display this text.\n\n"; 

}

sub printLC {

  my $msg = shift;
  my $show = shift;
  my @temp;
  my $logmsg;
  my $t = time;
  my $timestamp = strftime "%F %T", localtime $t;


  $timestamp .= sprintf ".%03d", ($t-int($t))*1000; # without rounding

  @temp = split('> ', $msg);
  $logmsg = $temp[1];

  if ($show) {
    print "$msg";
  }
  print $LOG "$timestamp : - $HOST - $logmsg";

}

sub printVer {

  print "\nsucicideCrypt version $VERSION\n\n";

}

sub getUUID {
  my $device = shift;
  my $luksCmd = "cryptsetup luksDump $device";
  my $result;
  my @temp;
  my $line;
  my $uuid;

  $result = `$luksCmd`;
  @temp = split(/\n/, $result);
  foreach $line (@temp) {
    if ($line =~ /^UUID/) {
      $uuid = (split(' ', $line))[1];
    }
  }
  return $uuid;
}


### Kicks off the logger for full execution trail
sub logStart {
  my $msg = shift;

  open($LOG, '>>', $LOGFILE) or die "Could not open logfile '$LOGFILE' $!";
  $msg = "\n-> Opening Log file to begin a " . "$msg" . " event\n";
  printLC($msg, $VERBOSE);
}

### Closes logger 
sub logClose {

  printLC("-> Operation complete closing logfile $LOGFILE\n", $VERBOSE);
  close $LOG;

}

### EOF ###
