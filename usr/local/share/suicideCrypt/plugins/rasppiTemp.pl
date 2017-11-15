#!/usr/bin/perl

my $cputemp0;
my $alarmtemp = 30;

$cputemp0 = `cat /sys/class/thermal/thermal_zone0/temp`;
chomp $cputemp0;

$cputemp0 = $cputemp0/1000;

$cputemp0 = int ($cputemp0);

if ($cputemp0 > $alarmtemp) {
  print "OK";
} else {
  print "pi-temp;$cputemp0;CPU temp $cputemp0 has dropped below $alarmtemp";
}
