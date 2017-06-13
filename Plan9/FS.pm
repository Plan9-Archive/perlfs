# Copyright © 2016-2017 by Yaroslav Kolomiiets
package Plan9::FS;
use Plan9;
use Plan9::IO;
use Symbol;

sub fsinit(*) {
	my $io = Symbol::qualify_to_ref(shift, caller);
	my (%fs, $fs);

	$fs = \%fs;
	$fs->{io} = $io;
	$fs->{ref} = 1;
	$fs->{freefid} = [];

	fsversion($fs, 8192, Plan9::VERSION9P)
		or return undef;

	return $fs;
}

sub fsmount(*;$) {
	my $io = Symbol::qualify_to_ref(shift, caller);
	my $aname = shift;
	my ($fs, $fid, $uname);

	$uname = $ENV{USER} || $ENV{LOGNAME} || $ENV{user} || 'none';
	$fs = fsinit($io);
	if(!defined $fs){
		return undef;
	}
	$fid = fsattach($fs, undef, $uname, $aname);
	fssetroot($fs, $fid);
	return $fs;
}

sub fsunmount($) {
	my $fs = shift;

	fsclose($fs->{root});
	$fs->{root} = undef;
	_fsdecref($fs);
}

sub _fsdecref($) {
	my $fs = shift;

	lock $fs;
	$fs->{ref}--;
	if($fs->{ref} == 0){
		close($fs->{io});
		while(@{$fs->{freefid}} > 0){
			pop(@{$fs->{freefid}})->{fs} = undef;
		}
	}
}

sub _fsgetfid($) {
	my $fs = shift;
	my $f;

	do {
		lock $fs;
		if(@{$fs->{freefid}} == 0){
			push(@{$fs->{freefid}}, {fid=>$fs->{nextfid}++, fs=>$fs});
		}
		$f = pop(@{$fs->{freefid}});
		$fs->{ref}++;
	};
	$f->{offset} = 0;
	$f->{mode} = -1;
	$f->{iounit} = 0;
	$f->{qid} = {path=>0, vers=>0, type=>0};
	return $f;
}

sub _fsputfid($) {
	my $fid = shift;
	my $fs;

	$fs = $fid->{fs};
	do {
		lock $fs;
		push(@{$fs->{freefid}}, $fid);
	};
	_fsdecref($fs);
}

sub _fsrpc($\%) {
	my ($fs, $t) = @_;
	my $r;

	if($Plan9::FS::chatty){
		print STDERR sprintf("-> %s\n", Plan9::Dbg::fcallstr($t));
	}
	Plan9::IO::writefcall($fs->{io}, %$t)
		or die "writefcall: $@";
	$r = Plan9::IO::readfcall($fs->{io}, $fs->{msize});
	if(!defined $r){
		return undef;
	};
	if($Plan9::FS::chatty){
		print STDERR sprintf("<- %s\n", Plan9::Dbg::fcallstr($r));
	}
	if($r->{type} == Plan9::Rerror){
		$@ = $r->{ename};
		return undef;
	}
	if($r->{type} != $t->{type}+1){
		$@ = sprintf("packet type mismatch -- tx %d rx %d", $t->{type}, $r->{type});
		return undef;
	}
	return $r;
}

sub fsversion($;$$) {
	my ($fs, $msize, $version) = @_;
	my ($t, $r);

	$fs->{msize} = $msize;

	$t = {
		type => Plan9::Tversion,
		tag => Plan9::NOTAG,
		version => $version,
		msize => $msize,
	};
	$r = _fsrpc($fs, %$t)
		or return undef;
	if($r->{msize} < $fs->{msize}){
		$fs->{msize} = $r->{msize};
	}
	$fs->{version} = $r->{version};
	return $r->{msize};
}

sub fsattach($;$$$$) {
	my ($fs, $afid, $uname, $aname) = @_;
	my ($t, $r, $fid, $err);

	$fid = _fsgetfid($fs);

	$t = {
		type=> Plan9::Tattach,
		tag=> 0,
		fid=> $fid->{fid},
		afid=> defined $afid? $afid->{fid} : Plan9::NOFID,
		uname=> $uname,
		aname=> $aname,
	};
	$r = _fsrpc($fs, %$t);
	if(!defined $r){
		_fsputfid($fid);
		return undef;
	}
	$fid->{qid} = $r->{qid};
	return $fid;
}

sub fssetroot($$) {
	my ($fs, $fid) = @_;

	$fs->{root} = $fid;
}

sub fswalk($;@) {
	my ($fid, @wname) = @_;
	my ($t, $r, $wfid);

	$wfid = _fsgetfid($fid->{fs});

	$t = {
		type => Plan9::Twalk,
		tag => 0,
		fid => $fid->{fid},
		newfid => $wfid->{fid},
		wname => \@wname,
	};
	$r = _fsrpc($fid->{fs}, %$t);
	if(!defined $r){
		_fsputfid($wfid);
		return undef;
	}
	if(@{$t->{wname}} != @{$r->{wqid}}){
		if(@{$r->{wqid}} > 0){
			$name = join('/', @{$t->{wname}}[0..int(@{$r->{wqid}})]);
		}
		$@ = sprintf("file '%s' not found", $name);
		_fsputfid($wfid);
		return undef;
	}
	if(@{$r->{wqid}} == 0){
		%{$wfid->{qid}} = %{$fid->{qid}};
	}else{
		$wfid->{qid} = pop @{$r->{wqid}};
	}
	return $wfid;
}

sub fswalkp($$) {
	my ($fid, $name) = @_;
	my @wname;

	@wname = grep {$_ ne '' and $_ ne '.'} split('/', $name);
	return fswalk($fid, @wname);
}

sub fsfcreate($$$$)
{
	my ($fid, $name, $mode, $perm) = @_;
	my ($t, $r);

	$t = {
		type=> Plan9::Tcreate,
		tag=> 0,
		fid=> $fid->{fid},
		name=> $name,
		mode=> $mode,
		perm=> $perm,
	};
	$r = _fsrpc($fid->{fs}, %$t);
	if(!defined $r){
		return -1;
	}
	$fid->{mode} = $mode;
	$fid->{qid} = $r->{qid};
	$fid->{iounit} = $r->{iounit};
	return 0;
}

sub fscreate($$$$) {
	my ($fs, $name, $mode, $perm) = @_;
	my (@p, $dir, $elem, $fid);

	@p = split('/', $name);
	$elem = pop @p;
	$dir = join('/', @p);

	$fid = fswalkp($fs->{root}, $dir);
	if(!defined $fid){
		return undef;
	}
	if(fsfcreate($fid, $elem, $mode, $perm) < 0){
		fsclose($fid);
		return undef;
	}
	return $fid;
}

sub fsfopen($$) {
	my ($fid, $mode) = @_;
	my ($t, $r);

	$t = {
		type=> Plan9::Topen,
		tag=> 0,
		fid=> $fid->{fid},
		mode=> $mode,
	};
	$r = _fsrpc($fid->{fs}, %$t);
	if(!defined $r){
		return -1;
	}
	$fid->{mode} = $mode;
	$fid->{qid} = $r->{qid};
	$fid->{iounit} = $r->{iounit};
	return 0;
}

sub fsopen($$$) {
	my ($fs, $name, $mode) = @_;
	my ($fid);

	$fid = fswalkp($fs->{root}, $name);
	if(!defined $fid){
		return undef;
	}
	if(fsfopen($fid, $mode) < 0){
		fsclose($fid);
		return undef;
	}
	return $fid;
}

sub fsiounit($) {
	my ($fid) = @_;
	if($fid->{iounit} > 0){
		return $fid->{iounit};
	}
	return $fid->{fs}->{msize} - Plan9::IOHDRSZ;
}

sub
fsclose($)
{
	my $fid = shift;
	my ($t, $r);

	if(!defined $fid){
		return;
	}
	$t = {
		type=> Plan9::Tclunk,
		tag=> 0,
		fid=> $fid->{fid}
	};
	_fsrpc($fid->{fs}, %$t);
	_fsputfid($fid);
}

sub fsfremove($) {
	my $fid = shift;
	my ($t, $r);

	if(!defined $fid){
		return;
	}
	$t = {
		type=>Plan9::Tremove,
		tag=>0,
		fid=>$fid->{fid}
	};
	$r = _fsrpc($fid->{fs}, %$t);
	if(!defined $r){
		return -1;
	}
	_fsputfid($fid);
	return 0;
}

sub fsremove($$) {
	my $fs = shift;
	my $name = shift;
	my $fid;

	$fid = fswalkp($fs->{root}, $name);
	if(!defined $fid){
		return -1;
	}
	return fsfremove($fid);
}

sub fspwrite($$$) {
	my ($fid, $data, $offset) = @_;
	my ($t, $r);

	$t = {
		type => Plan9::Twrite,
		tag => 0,
		fid => $fid->{fid},
		data => $data,
		offset => $offset,
	};
	$r = _fsrpc($fid->{fs}, %$t);
	if(!defined $r){
		return -1;
	}
	return $r->{count};
}

sub fswrite($$) {
	my ($fid, $data) = @_;
	my ($offset, $count);

	do {
		lock $fid;
		$offset = $fid->{offset};
	};
	$count = fspwrite($fid, $data, $offset);
	if($count > 0){
		lock $fid;
		$fid->{offset} += $count;
	}
	return $count;
}

sub fsprintf($@) {
	my $fid = shift;
	my $fmt = shift;

	return fswrite($fid, sprintf($fmt, @_));
}

sub fspread($$$) {
	my ($fid, $count, $offset) = @_;
	my ($t, $r, $data);

	$t = {
		type => Plan9::Tread,
		tag => 0,
		fid => $fid->{fid},
		count => $count,
		offset => $offset,
	};
	$r = _fsrpc($fid->{fs}, %$t);
	if(!defined $r){
		return undef;
	}
	return $r->{data};
}

sub fsread($$) {
	my ($fid, $count) = @_;
	my ($data, $offset);

	do {
		lock $fid;
		$offset = $fid->{offset};
	};
	$data = fspread($fid, $count, $offset);
	if(!defined $data){
		return undef;
	}
	do {
		lock $fid;
		$fid->{offset} += length($data);
	};
	return $data;
}

sub fsdirfstat($) {
	my ($fid) = @_;
	my ($t, $r);

	$t = {
		type => Plan9::Tstat,
		tag => 0,
		fid => $fid->{fid},
	};
	$r = _fsrpc($fid->{fs}, %$t);
	if(!defined $r){
		return undef;
	}
	return $r->{stat};
}

sub fsdirstat($$) {
	my ($fs, $name) = @_;
	my ($fid, $d);

	$fid = fswalkp($fs->{root}, $name);
	if(!defined $fid){
		return -1;
	}
	$d = fsdirfstat($fid);
	fsclose($fid);
	return $d;
}

sub fsdirfwstat($\%) {
	my ($fid, $d) = @_;
	my ($t, $r);

	$t = {
		type => Plan9::Twstat,
		tag => 0,
		fid => $fid->{fid},
		stat => $d,
	};
	$r = _fsrpc($fid->{fs}, %$t);
	if(!defined $r){
		return -1;
	}
	return 0;
}

sub fsdirwstat($$\%) {
	my ($fs, $name, $d) = @_;
	my ($fid, $n);

	$fid = fswalkp($fs->{root}, $name);
	if(!defined $fid){
		return -1;
	}
	$n = fsdirfwstat($fid, %$d);
	fsclose($fid);
	return $n;
}

sub fsdirread($) {
	my ($fid) = @_;
	my ($dirmax, $m);

	$dirmax = $fid->{fs}->{msize};

	$m = fsread($fid, $dirmax);
	if(!defined $m){
		return ();
	}
	return Plan9::unpackdir($m);
}

sub fsdirreadall($) {
	my ($fid) = @_;
	my (@d, @dall);

	for(;;){
		@d = fsdirread($fid);
		if(@d == 0){
			last;
		}
		push(@dall, @d);
	}
	return @dall;
}

1;
