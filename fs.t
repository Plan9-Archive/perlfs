package main;
use strict;
use Plan9::FS;
#	use Plan9::Dbg;	# enables 9P trace on fd 2
use Socket;
use IO::Handle;		# for autoflush
use Data::Dumper;

my ($fs, $f, $f1, $s, $n, $d, @d);

#$ENV{NAMESPACE} = "/tmp/ns.$ENV{USER}.$ENV{DISPLAY}"
#	unless defined $ENV{NAMESPACE};
#my $conn = "$ENV{NAMESPACE}/factotum";
#socket(S9, PF_UNIX, SOCK_STREAM, 0) or die "socket: $!";
#connect(S9, sockaddr_un($conn)) or die "connect: $!";
#
# 	rm -f /srv/rrr && ramfs -DsS rrr
#
open(S9, "</srv/rrr")	or die "open /srv/rrr: $!";

STDOUT->autoflush(1);
STDERR->autoflush(1);

$fs = Plan9::FS::fsmount(\*S9, '');
if(!defined $fs){
	print STDERR "fsmount: $@\n";
	exit 1;
}
	
$f = Plan9::FS::fsopen($fs, ".", 0);
if(!defined $f){
	print STDERR "open: $@\n";
}else{
	@d = Plan9::FS::fsdirreadall($f);
	for(@d){
		print "\t", $_->{name}, "\n";
	}
	Plan9::FS::fsclose($f);
}

$f1 = Plan9::FS::fscreate($fs, "x", 0, Plan9::DMDIR | 0775);
if(!defined $f1){
	print STDERR "create: $@\n";
}
$f = Plan9::FS::fscreate($fs, "x/yy", 2, 0664);
if(!defined $f){
	print STDERR "create: $@\n";
}
Plan9::FS::fswrite($f, "hello");
Plan9::FS::fsprintf($f, ", %s!", 'world');
Plan9::FS::fsclose($f);
Plan9::FS::fsclose($f1);

%{$d} = %Plan9::syncdir;
$d->{name} = "y";
if(Plan9::FS::fsdirwstat($fs, "x/yy", %$d) < 0){
	print STDERR "wstat: $@\n";
}

$d = Plan9::FS::fsdirstat($fs, "x/y");
if(!defined $d){
	print STDERR "stat: $@\n";
}else{
	if(exists $Plan9::Dbg::{'&dirstr'}){
		print "stat ok: ", Plan9::Dbg::dirstr($d), "\n";
	}
}

$f = Plan9::FS::fsopen($fs, "x/y", 0);
if(!defined $f){
	print STDERR "open: $@\n";
}
print "read ok: ", Plan9::FS::fsread($f, Plan9::FS::fsiounit($f)), "\n";
Plan9::FS::fsclose($f);
if(Plan9::FS::fsremove($fs, "x/y") < 0){
	print STDERR "remove: $@\n";
}
$f = Plan9::FS::fscreate($fs, "x/z", 2, 0664);
if(!defined $f){
	print STDERR "create: $@\n";
}
if(Plan9::FS::fsfremove($f) < 0){
	print STDERR "remove: $@\n";
}
if(Plan9::FS::fsremove($fs, "x") < 0){
	print STDERR "remove: $@\n";
}

$f = Plan9::FS::fswalk($fs->{root});
if(!defined($f)){
	print STDERR "walk: $@\n";
}
$d = Plan9::FS::fsdirfstat($f);
if(!defined $d){
	print STDERR "stat: $@\n";
}else{
	if(exists $Plan9::Dbg::{'&dirstr'}){
		print "stat ok: ", Plan9::Dbg::dirstr($d), "\n";
	}
}
Plan9::FS::fsunmount($fs);
Plan9::FS::fsclose($f);
