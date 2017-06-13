package main;
use strict;
use warnings;
use Plan9::Srv;
#	use Plan9::Dbg;	# enables 9P trace on fd 2

use constant {
	Qtop 	=>	0,
	Qdate	=>	1,
};

sub QID {
	my ($path) = @_;
	my %qtab = (
		&Qtop =>	{path=>$path, vers=>0, type=>Plan9::QTDIR},
		&Qdate =>	{path=>$path, vers=>0, type=>0},
	);
	return $qtab{FILE($path)};
}

sub QPATH {
	my ($file) = @_;
	return $file;
}

sub FILE {
	my ($path) = @_;
	return $path&0xff;
}

sub fsattach {
	my ($r) = @_;
	my $qid;

	$qid = QID(Qtop);
	$r->{fid}->{qid} = $qid;
	$r->{ofcall}->{qid} = $qid;
	Plan9::Srv::respond($r);
}

sub fswalk {
	my ($r) = @_;
	my ($path, @wqid);

	$path = $r->{fid}->{qid}->{path};

Walk:
	for(@{$r->{ifcall}->{wname}}){
		if($_ eq '..'){
			push(@wqid, QID($path = Qtop));
			next;
		}
		if($path == Qtop and $_ eq 'date') {
			push(@wqid, QID($path = Qdate));
			next;
		}
		last;
	}
	$r->{ofcall}->{wqid} = \@wqid;
	Plan9::Srv::respond($r);
}

sub getstat {
	my ($path) = @_;
	my ($d, $fntab);

	$d = {};
	%{$d} = %Plan9::nulldir;
	$d->{qid} = QID($path);
	$d->{uid} = $d->{gid} = $d->{muid} = "perl";
	$d->{mode} = 0444;

	$fntab = {
		&Qtop =>  	sub {
			$d->{name} = ".";
		},
		&Qdate =>	sub {
			$d->{name} = "date";
			$d->{length} = 29;
		},
	};
	&{$fntab->{FILE($path)}}();

	if($d->{qid}->{type}&Plan9::QTDIR){
		$d->{mode} |= Plan9::DMDIR | 0111;
	}
	return $d;
}

sub fsstat {
	my ($r) = @_;

	$r->{d} = getstat($r->{fid}->{qid}->{path});
	Plan9::Srv::respond($r);
}

sub fsread {
	my ($r) = @_;
	my ($path, $gen);

	$path = $r->{fid}->{qid}->{path};

	if($path == Qtop){
		$gen = sub {
			return undef unless exists $_[$_];
			return getstat($_[$_]);
		};
		Plan9::Srv::dirread9p($r, $gen, Qdate);
		Plan9::Srv::respond($r);
	}elsif($path == Qdate){
		Plan9::Srv::readstr($r, `date`);
		Plan9::Srv::respond($r);
	}else{
		Plan9::Srv::respond($r, "programming error in fsread");
	}
}

my $srv = {
	ior => \*STDIN,
	iow => \*STDOUT,
	attach => \&fsattach,
	walk => \&fswalk,
	read => \&fsread,
	stat => \&fsstat,
};

Plan9::Srv::srv($srv);

#
#	slay Perl |rc
# 	rm -f /srv/p; srv -e 'Perl $%' p /n/local; ls -lq /n/local/date
#	
# --r--r--r--  0 perl perl 29 Jan  1  1970 /n/local/date
