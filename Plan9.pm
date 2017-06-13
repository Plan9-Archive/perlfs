#!/usr/bin/perl
# Copyright © 2016-2017 by Yaroslav Kolomiiets
package Plan9;

use strict;
use constant {
	VERSION9P=>	'9P2000',
	MAXWELEM=>	16,
	IOHDRSZ=>	24,
	NOTAG=>	0xffff,
	NOFID=>	0xffffffff,

	# bits in Qid.type
	QTDIR		=> 0x80,	# type bit for directories
	QTAPPEND	=> 0x40,	# type bit for append only files
	QTEXCL		=> 0x20,	# type bit for exclusive use files
	QTMOUNT	=> 0x10,	# type bit for mounted channel
	QTAUTH		=> 0x08,	# type bit for authentication file
	QTTMP		=> 0x04,	# type bit for not-backed-up file
	QTFILE		=> 0x00,	# plain file

	# bits in Dir.mode
	DMDIR =>		0x80000000,	# mode bit for directories
	DMAPPEND=>	0x40000000,	# mode bit for append only files
	DMEXCL      => 0x20000000,	# mode bit for exclusive use files
	DMMOUNT     => 0x10000000,	# mode bit for mounted channel
	DMAUTH      => 0x08000000,	# mode bit for authentication file
	DMTMP       => 0x04000000,	# mode bit for non-backed-up files
	DMREAD      => 0x4,	# mode bit for read permission
	DMWRITE     => 0x2,	# mode bit for write permission
	DMEXEC      => 0x1,	# mode bit for execute permission

	# open modes
	OREAD     => 0,		# open for read	
	OWRITE    => 1,		# write
	ORDWR     => 2,	# read and write
	OEXEC     => 3,		# execute, == read but check execute permission
	OTRUNC    => 16,	# or'ed in (except for exec), truncate file first
	OCEXEC    => 32,	# or'ed in, close on exec
	ORCLOSE   => 64,	# or'ed in, remove on close
	OEXCL   => 0x1000,	# or'ed in, exclusive use (create only)
};
use constant {
	Tversion	=> 100,
	Rversion	=> 101,
	Tauth	=> 102,
	Rauth	=> 103,
	Tattach	=> 104,
	Rattach	=> 105,
	Terror	=> 106, # illegal
	Rerror	=> 107,
	Tflush	=> 108,
	Rflush	=> 109,
	Twalk	=> 110,
	Rwalk	=> 111,
	Topen	=> 112,
	Ropen	=> 113,
	Tcreate	=> 114,
	Rcreate	=> 115,
	Tread	=> 116,
	Rread	=> 117,
	Twrite	=> 118,
	Rwrite	=> 119,
	Tclunk	=> 120,
	Rclunk	=> 121,
	Tremove	=> 122,
	Rremove	=> 123,
	Tstat	=> 124,
	Rstat	=> 125,
	Twstat	=> 126,
	Rwstat	=> 127,
	Tmax	=> 128,
};

our %nulldir = (
	type => 0,
	dev => 0,
	qid => {
		type => 0,
		vers => 0,
		path => 0,
	},
	mode => 0,
	atime => 0,
	mtime => 0,
	length => 0,
	name => "",
	uid => "",
	gid => "",
	muid => "",
);

our %syncdir = (
	type => ~0 & 0xffff,
	dev => ~0 & 0xffffffff,
	qid => {
		type => ~0 & 0xff,
		vers => ~0 & 0xffffffff,
		path => ~0,
	},
	mode => ~0 & 0xffffffff,
	atime => ~0 & 0xffffffff,
	mtime => ~0 & 0xffffffff,
	length => ~0,
	name => "",
	uid => "",
	gid => "",
	muid => "",
);

sub packvlong($) {
	local ($_) = @_;
	my ($lo, $hi);

	$lo = $_;
	$hi = 0;
	if($lo == ~0){
		$hi = ~0;
	}
	return pack("VV", $lo, $hi);
}

sub unpackvlong($) {
	local ($_) = @_;
	my ($lo, $hi);

	($lo, $hi) = unpack("VV", $_);
	if($hi != 0){
		$lo = ~0;
	}
	return $lo;
}

sub cmpvlong($$) {
	my ($a, $b) = @_;
	return $a-$b;
}

sub packqid(\%) {
	local $_ = shift;
	my $a;

	# qid.type[1] qid.vers[4] qid.path[8]
	$_->{_path} = packvlong($_->{path});
	$a = pack("CVa[8]", @{$_}{'type', 'vers', '_path'});
	delete $_->{_path};
	return $a;
}

sub unpackqid($) {
	my $m = shift;
	local $_ = {};

	@{$_}{'type', 'vers', 'path'} = unpack("CVa[8]", $m);
	$_->{path} = unpackvlong($_->{path});
	return $_;
}

sub packdir(\%) {
	my $d = shift;
	my $a;

	$d->{_length} = packvlong($d->{length});
	$d->{_qid} = packqid(%{$d->{qid}});
	$a = pack("v/a*", pack("vVa[13]VVVa[8]v/a*v/a*v/a*v/a*",
		@{$d}{qw(type dev _qid mode atime mtime _length name uid gid muid)}));
	delete $d->{_length};
	delete $d->{_qid};
	return $a;
}

sub unpackdir($) {
	my $m = shift;
	my ($d, $dm, @d, $size);

	for $dm (unpack("(v/a)*", $m)){
		$d = {};
		@{$d}{qw(type dev qid mode atime mtime length name uid gid muid)} =
			unpack("vVa[13]VVVa[8]v/a*v/a*v/a*v/a*", $dm);
		$d->{length} = unpackvlong($d->{length});
		$d->{qid} = unpackqid($d->{qid});
		return $d unless wantarray;
		push(@d, $d);
	}
	return @d;
}

sub packfcall(\%) {
	my ($f) = @_;
	my ($size, $ap, $p, $m, $fntab, $fn);

	$fntab = {	
		&Tversion =>	sub { pack("Vv/a*", @$f{'msize','version'}) },
		&Rversion =>	sub { pack("Vv/a*", @$f{'msize','version'}) },
		&Tauth =>	sub { pack("Vv/a*v/a*", @{$f}{'afid','uname','aname'}) },
		&Rauth =>	sub { packqid(%{$f->{aqid}}) },
		&Rerror =>	sub { pack("v/a*", $f->{ename}) },
		&Tflush =>	sub { pack("v", ${$f}{oldsize}) },
		&Rflush =>	sub { '' },
		&Tattach =>	sub { pack("VVv/a*v/a*", @$f{qw(fid afid uname aname)}) },
		&Rattach =>	sub { packqid(%{$f->{qid}}); },
		&Twalk =>	sub { pack("VVv", @$f{'fid','newfid'}, 0+@{$f->{wname}}) . join('', map {pack("v/a*", $_)} @{$f->{wname}}) },
		&Rwalk =>	sub { pack("v", 0+@{$f->{wqid}}) . join('', map {packqid(%{$_})} @{$f->{wqid}}) },
		&Topen =>	sub { pack("VC", @$f{'fid','mode'}) },
		&Ropen =>	sub { pack("a[13]V", @$f{'qid', 'iounit'}) },
		&Tcreate =>	sub { pack("Vv/a*VC", @$f{'fid','name','perm','mode'}) },
		&Rcreate =>	sub { pack("a[13]V", packqid(%{$f->{qid}}), $f->{iounit}); },
		&Tread =>	sub { pack("Va[8]V", $f->{fid}, packvlong($f->{offset}), $f->{count}) },
		&Rread =>	sub { pack("V/a*", $f->{data}); },
		&Twrite =>	sub { pack("Va[8]V/a*", $f->{fid}, packvlong($f->{offset}), $f->{data}) },
		&Rwrite =>	sub { pack("V", $f->{count}) },
		&Tclunk =>	sub { pack("V", $f->{fid}) },
		&Rclunk =>	sub { '' },
		&Tremove =>	sub { pack("V",  $f->{fid}) },
		&Rremove =>	sub { '' },
		&Tstat =>  	sub { pack("V", $f->{fid}) },
		&Rstat =>  	sub { pack("v/a*", packdir(%{$f->{stat}})) },
		&Twstat =>	sub { pack("Vv/a*", $f->{fid}, packdir(%{$f->{stat}})) },
		&Rwstat =>	sub { '' },
	};
	$fn = $fntab->{$f->{type}};
	if(!defined $fn){
		$@ = "bad Fcall.type";
		return undef;
	}
	$p = &$fn();
	$size = 7+length($p);
	$ap = pack("VCv", $size, @{$f}{'type', 'tag'});
	return $ap.$p;
}

sub unpackfcall($) {
	my ($ap) = @_;
	my ($f, $nap, $p, $size, %qid, $fntab, $fn);

	$nap = length($ap);
	if($nap < 7){
		$@ = "short message";
		return undef;
	}
	$size = unpack("V", $ap);
	if($size < 7 or $size > $nap){
		$@ = "bad length in Fcall header";
		return undef;
	}

	$f = {};
	(undef, $f->{type}, $f->{tag}, $p) = unpack("VCva*", $ap);
	$fntab = {
		&Tversion =>	sub { @{$f}{'msize','version'} = unpack("Vv/a", $p) },
		&Rversion =>	sub { @{$f}{'msize','version'} = unpack("Vv/a", $p) },
		&Tauth =>	sub { @{$f}{'afid','uname','aname'} = unpack("Vv/av/a", $p) },
		&Rauth =>	sub { ${$f}{aqid} = unpackqid($p) },
		&Rerror =>	sub { ${$f}{ename} = unpack("v/a", $p) },
		&Tflush =>	sub { ${$f}{oldtag} = unpack("v", $p) },
		&Rflush =>	sub { },
		&Tattach =>	sub { @{$f}{'fid','afid','uname','aname'} = unpack("VVv/av/a", $p) },
		&Rattach =>	sub { ${$f}{qid} = unpackqid($p) },
		&Twalk =>	sub {
			@{$f}{'fid','newfid','nwname'} = unpack("VVv", $p);
			if($f->{nwname} > MAXWELEM){
				die "name too long";
			}
			${$f}{wname} = [];
			(undef, undef, undef, @{$f->{wname}}) = unpack("VVv" . "v/a"x$f->{nwname}, $p);
		},
		&Rwalk =>	sub {
			$f->{wqid} = [map {unpackqid($_)} unpack("v/(a[13])", $p)];
		},
		&Topen =>	sub { @{$f}{'fid','mode'} = unpack("VC", $p) },
		&Ropen =>	sub {
			@{$f}{'qid','iounit'} = unpack("a[13]V", $p);
			$f->{qid} = unpackqid($f->{qid});
		},
		&Tcreate =>	sub { @{$f}{'fid','name','perm','mode'} = unpack("Vv/aVC", $p) },
		&Rcreate =>	sub {
			@{$f}{'qid', 'iounit'} = unpack("a[13]V", $p);
			$f->{qid} = unpackqid($f->{qid});
		},
		&Tread =>	sub {
			@{$f}{'fid','offset','count'} = unpack("Va[8]V", $p);
			${$f}{offset} = unpackvlong(${$f}{offset});
		},
		&Rread =>	sub { @{$f}{'count','data'} = unpack("VX[V]V/a", $p) },
		&Twrite =>	sub {
			@{$f}{'fid','offset','count','data'} = unpack("Va[8]VX[V]V/a", $p);
			${$f}{offset} = unpackvlong(${$f}{offset});
		},
		&Rwrite =>	sub { ${$f}{count} = unpack("V", $p) },
		&Tclunk =>	sub { ${$f}{fid} = unpack("V", $p) },
		&Rclunk =>	sub { },
		&Tremove =>	sub { ${$f}{fid} = unpack("V", $p) },
		&Rremove =>	sub { },
		&Tstat =>  	sub { ${$f}{fid} = unpack("V", $p) },
		&Rstat =>  	sub { ${$f}{stat} = unpackdir(unpack("v/a*", $p)) },
		&Twstat =>	sub {
			@{$f}{'fid','stat'} = unpack("Vv/a*", $p);
			${$f}{stat} = unpackdir(${$f}{stat});
		},
		&Rwstat =>	sub { },
	};
	eval {
		$fn = $fntab->{$f->{type}};
		if(!defined $fn){
			die "bad Fcall.type $f->{type}";
		}
		&$fn();
	};
	if(length($@) > 0){
		return undef;
	}
	return $f;
}

1;
