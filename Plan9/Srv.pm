# Copyright © 2016-2017 by Yaroslav Kolomiiets
package Plan9::Srv;
use Plan9::IO;
	use Data::Dumper;
use strict;

#BEGIN {
#	$Plan9::Srv::{Tversion} = \&{"Plan9::Tversion"};
#}

sub _getreq($) {
	my ($srv) = @_;
	my ($f, $r);

	do {
		lock($srv->{rlock});
		$f = Plan9::IO::readfcall($srv->{ior}, $srv->{msize});
	};
	if(!defined $f){
		return undef;
	}
	$r = {
		srv => $srv,
		responded => 0,
		ifcall => $f,
		ofcall => {},
		type => $f->{type},
		tag => $f->{tag},
	};

	if($Plan9::Srv::chatty){
		print STDERR sprintf("<-%d- %s\n", fileno($srv->{ior}), Plan9::Dbg::fcallstr($f));
	}
	
	return $r;	
}

sub srv($) {
	my ($srv) = @_;
	my ($r, $fntab, $fn);

	if(!defined $srv->{msize}){
		$srv->{msize} = 8192;
	}

	$fntab = {
		&Plan9::Tversion =>	\&sversion,
		&Plan9::Tauth =>	\&sauth,
		&Plan9::Tattach =>	\&sattach,
		&Plan9::Tflush =>	\&sflush,
		&Plan9::Twalk =>	\&swalk,
		&Plan9::Topen =>	\&sopen,
		&Plan9::Tcreate =>	\&screate,
		&Plan9::Tread =>	\&sread,
		&Plan9::Twrite =>	\&swrite,
		&Plan9::Tclunk =>	\&sclunk,
		&Plan9::Tremove =>	\&sremove,
		&Plan9::Tstat =>	\&sstat,
		&Plan9::Twstat => \&swstat,
	};

	while(defined($r = _getreq($srv))){
		$fn = $fntab->{$r->{type}};
		if(!defined $fn){
			respond($r, "unknown message");
		}else{
			&$fn($r);
		}
	}
}

sub respond($;$) {
	my ($r, $error) = @_;
	my ($srv, $fntab, $fn);

	$srv = $r->{srv};
	die unless defined $srv;

	die if $r->{responded};
	$r->{error} = $error;

	$fntab = {
		&Plan9::Tversion =>	\&rversion,
		&Plan9::Tauth =>	\&rauth,
		&Plan9::Tattach =>	\&rattach,
		&Plan9::Tflush =>	\&rflush,
		&Plan9::Twalk =>	\&rwalk,
		&Plan9::Topen =>	\&ropen,
		&Plan9::Tcreate =>	\&rcreate,
		&Plan9::Tread =>	\&rread,
		&Plan9::Twrite =>	\&rwrite,
		&Plan9::Tclunk =>	\&rclunk,
		&Plan9::Tremove =>	\&rremove,
		&Plan9::Tstat =>	\&rstat,
		&Plan9::Twstat => \&rwstat,
	};
	$fn = $fntab->{$r->{type}};
	die unless defined $fn;
	&$fn($r);

	$r->{ofcall}->{tag} = $r->{ifcall}->{tag};
	$r->{ofcall}->{type} = $r->{ifcall}->{type}+1;
	if($r->{error}){
		$r->{ofcall}->{type} = Plan9::Rerror;
		$r->{ofcall}->{ename} = $r->{error};
	}

	if($Plan9::Srv::chatty){
		print STDERR sprintf("-%d-> %s\n", fileno($srv->{iow}), Plan9::Dbg::fcallstr($r->{ofcall}));
		print STDERR Data::Dumper->Dump([$r], ['$r']) if $Plan9::Srv::chatty > 1;
	}

	Plan9::IO::writefcall($srv->{iow}, %{$r->{ofcall}})
		or die "writefcall: $@";
	$r->{responded} = 1;
}

sub sversion {
	my ($r) = @_;

	if(substr($r->{ifcall}->{version}, 0, 2) ne "9P"){
		$r->{ofcall}->{version} = "unknown";
		respond($r, undef);
		return;
	}

	$r->{ofcall}->{version} = "9P2000";
	$r->{ofcall}->{msize} = $r->{ifcall}->{msize};
	respond($r, undef);
}

sub rversion {
	my ($r) = @_;

	$r->{srv}->{msize} = $r->{ofcall}->{msize};
}

sub sauth {
	my ($r) = @_;
	my $srv;

	$srv = $r->{srv};

	if(!defined($r->{afid} = _allocfid($srv, $r->{ifcall}->{afid}))){
		respond($r, "duplicate fid");
	}

	if($srv->{auth}){
		&{$srv->{auth}}($r);
	}else{
		respond($r, "authentication not required");
	}
}

sub rauth {
	my ($r) = @_;

	if($r->{error} and $r->{afid}){
		_removefid($r->{srv}, $r->{afid}->{fid});
	}
}

sub sattach {
	my ($r) = @_;
	my $srv = $r->{srv};

	if(!defined($r->{fid} = _allocfid($srv, $r->{ifcall}->{fid}))){
		respond($r, "duplicate fid");
	}

	$r->{afid} = undef;
	if($r->{ifcall}->{afid} != Plan9::NOFID and !defined($r->{afid} = _lookupfid($srv, $r->{ifcall}->{afid}))){
		respond($r, "unknown fid");
	}

	$r->{fid}->{uid} = $r->{ifcall}->{uname};

	if($srv->{attach}){
		&{$srv->{attach}}($r);
	}else{
		respond($r, undef);
	}
}

sub rattach {
	my ($r) = @_;

	if($r->{error} and $r->{fid}){
		_removefid($r->{srv}, $r->{fid}->{fid});
	}
}

sub sflush {
	my ($r) = @_;
	
	respond($r, undef);
}

sub rflush {
	my ($r) = @_;
}

sub sclunk {
	my ($r) = @_;

	if(!defined($r->{fid} = _removefid($r->{srv}, $r->{ifcall}->{fid}))){
		respond($r, "unknown fid");
	}else{
		respond($r, undef);
	}
}

sub rclunk {
}

sub sremove {
	my ($r) = @_;

	if(!defined($r->{fid} = _removefid($r->{srv}, $r->{ifcall}->{fid}))){
		respond($r, "unknown fid");
		return;
	}
	if($r->{srv}->{remove}){
		&{$r->{srv}->{remove}}($r);
	}else{
		respond($r, "remove prohibited");
	}
}

sub rremove {
}

sub swalk {
	my ($r) = @_;

	if(!defined ($r->{fid} = _lookupfid($r->{srv}, $r->{ifcall}->{fid}))){
		respond($r, "unknown fid");
		return;
	}
	if($r->{fid}->{omode} != -1){
		respond($r, "cannot clone open fid");
		return;
	}
	if($r->{ifcall}->{nwname} and !($r->{fid}->{qid}->{type}&Plan9::QTDIR)){
		respond($r, "walk in non-directory");
		return;
	}
	if($r->{ifcall}->{fid} != $r->{ifcall}->{newfid}){
		if(!defined ($r->{newfid} = _allocfid($r->{srv}, $r->{ifcall}->{newfid}))){
			respond($r, "duplicate fid");
			return;
		}
		$r->{newfid}->{uid} = $r->{fid}->{uid};
	}else{
		$r->{newfid} = $r->{fid};
	}


	if($r->{srv}->{walk}){
		&{$r->{srv}->{walk}}($r);
	}else{
		respond($r, "no walk function");
	}
}

sub rwalk {
	my ($r) = @_;
	my $wqid;

	$wqid = $r->{ofcall}->{wqid};
	if(!defined $wqid){
		$wqid = [];
		$r->{ofcall}->{wqid} = $wqid;
	}

	if($r->{error} or @{$wqid} < @{$r->{ifcall}->{wname}}){
		if($r->{newfid} and $r->{ifcall}->{fid} != $r->{ifcall}->{newfid}){
			_removefid($r->{srv}, $r->{newfid}->{fid});
		}
		if(@{$wqid}==0){
			if(!defined($r->{error}) and @{$r->{ifcall}->{wname}}!=0){
				$r->{error} = "file not found";
			}
		}else{
			$r->{error} = undef;	# No error on partial walks
		}
	}else{
		if(@{$wqid} == 0){
			# Just a clone
			$r->{newfid}->{qid} = $r->{fid}->{qid};
		}else{
			$r->{newfid}->{qid} = ${$wqid}[@{$wqid}-1];
		}
	}
}

sub screate {
	my ($r) = @_;

	if(!defined ($r->{fid} = _lookupfid($r->{srv}, $r->{ifcall}->{fid}))){
		respond($r, "unknown fid");
		return;
	}
	if($r->{fid}->{omode} != -1){
		respond($r, "9P protocol botch");
		return;
	}
	if(!($r->{fid}->{qid}->{type}&Plan9::QTDIR)){
		respond($r, "create in non-directory");
		return;
	}

	if($r->{srv}->{create}){
		&{$r->{srv}->{create}}($r);
	}else{
		respond($r, "create prohibited");
	}
}

sub rcreate {
	my ($r) = @_;

	if($r->{error}){
		return;
	}
	$r->{fid}->{omode} = $r->{ifcall}->{mode};
	$r->{fid}->{qid} = $r->{ofcall}->{qid};
	if($r->{ofcall}->{qid}->{type}&Plan9::QTDIR){
		$r->{fid}->{diroffset} = 0;
	}
	if($Plan9::Srv::chatty){
		print STDERR sprintf("fid mode is 0x%x\n", $r->{fid}->{omode});
	}
}

sub sopen {
	my ($r) = @_;

	if(!defined ($r->{fid} = _lookupfid($r->{srv}, $r->{ifcall}->{fid}))){
		respond($r, "unknown fid");
		return;
	}
	if($r->{fid}->{omode} != -1){
		respond($r, "9P protocol botch");
		return;
	}
	if($r->{fid}->{qid}->{type}&Plan9::QTDIR
	and ($r->{ifcall}->{mode}&~Plan9::ORCLOSE) != Plan9::OREAD){
		respond($r, "is a directory");
		return;
	}
	$r->{ofcall}->{qid} = $r->{fid}->{qid};

	if($r->{srv}->{open}){
		&{$r->{srv}->{open}}($r);
	}else{
		respond($r);
	}
}

sub ropen {
	my ($r) = @_;

	if($r->{error}){
		return;
	}
	$r->{fid}->{omode} = $r->{ifcall}->{mode};
	$r->{fid}->{qid} = $r->{ofcall}->{qid};
	if($r->{ofcall}->{qid}->{type}&Plan9::QTDIR){
		$r->{fid}->{diroffset} = 0;
	}
	if($Plan9::Srv::chatty){
		print STDERR sprintf("fid mode is 0x%x\n", $r->{fid}->{omode});
	}
}

sub sread {
	my ($r) = @_;
	my ($o, $z);

	if(!defined ($r->{fid} = _lookupfid($r->{srv}, $r->{ifcall}->{fid}))){
		respond($r, "unknown fid");
		return;
	}
	$o = $r->{fid}->{omode}&3;
	if($o != Plan9::OREAD and $o != Plan9::ORDWR and $o != Plan9::OEXEC){
		respond($r, "not opened for reading");
		return;
	}
	if($r->{ifcall}->{count} < 0){
		respond($r, "9P protocol botch");
	}
	if($r->{ifcall}->{count} > $r->{srv}->{msize} - Plan9::IOHDRSZ){
		$r->{ifcall}->{count} = $r->{srv}->{msize} - Plan9::IOHDRSZ;
	}

	if($r->{ifcall}->{offset} < 0
	or (($r->{fid}->{qid}->{type}&Plan9::QTDIR) and $r->{ifcall}->{offset} != 0 and $r->{ifcall}->{offset} != $r->{fid}->{diroffset})){
		respond($r, "bad offset");
		return;
	}

	if($r->{srv}->{read}){
		&{$r->{srv}->{read}}($r);
	}else{
		respond($r, "no read function");
	}
}

sub rread {
	my ($r) = @_;

	if($r->{error}){
		return;
	}
	if($r->{fid}->{qid}->{type}&Plan9::QTDIR){
		$r->{fid}->{diroffset} += length($r->{ofcall}->{data});
	}
}

sub swrite {
	my ($r) = @_;
	my ($o, $z);

	if(!defined ($r->{fid} = _lookupfid($r->{srv}, $r->{ifcall}->{fid}))){
		respond($r, "unknown fid");
		return;
	}
	$o = $r->{fid}->{omode}&3;
	if($o != Plan9::OWRITE and $o != Plan9::ORDWR){
		respond($r, "not opened for writing");
		return;
	}
	if($r->{ifcall}->{offset} < 0){
		respond($r, "bad offset");
		return;
	}
	if($r->{ifcall}->{count} < 0){
		respond($r, "9P protocol botch");
	}
	if($r->{ifcall}->{count} > $r->{srv}->{msize} - Plan9::IOHDRSZ){
		$r->{ifcall}->{count} = $r->{srv}->{msize} - Plan9::IOHDRSZ;
	}

	if($r->{srv}->{write}){
		&{$r->{srv}->{write}}($r);
	}else{
		respond($r, "no write function");
	}
}

sub rwrite {
}

sub dirread9p {
	my ($r, $gen, @args) = @_;
	my ($d, $bits);
	local $_;
	
	if($r->{ifcall}->{offset} == 0){
		$_ = 0;
	}else{
		$_ = $r->{fid}->{dirindex};
	}
	while(defined ($d = &$gen(@args))){
		$bits = Plan9::packdir(%$d);
		if(!defined $bits or length($bits)+length($r->{ofcall}->{data}) > $r->{ifcall}->{count}){
			last;
		}
		$r->{ofcall}->{data} .= $bits;
		++$_;
	}
	$r->{fid}->{dirindex} = $_;
}

sub readstr {
	my ($r, $str) = @_;
	my ($offset, $count);

	$offset = $r->{ifcall}->{offset};
	$count = $r->{ifcall}->{count};

	if($offset < length($str)){
		$r->{ofcall}->{data} = substr($str, $offset, $count);
	}else{
		$r->{ofcall}->{data} = '';
	}
}

sub sstat {
	my ($r) = @_;

	if(!defined ($r->{fid} = _lookupfid($r->{srv}, $r->{ifcall}->{fid}))){
		respond($r, "unknown fid");
		return;
	}
	if($r->{srv}->{stat}){
		&{$r->{srv}->{stat}}($r);
	}else{
		respond($r, "stat prohibited");
	}
}

sub rstat {
	my ($r) = @_;

	if($r->{error}){
		return
	};
	if(defined $r->{d}){
		$r->{ofcall}->{stat} = $r->{d};
	}
}

sub swstat {
	my ($r) = @_;

	if(!defined ($r->{fid} = _lookupfid($r->{srv}, $r->{ifcall}->{fid}))){
		respond($r, "unknown fid");
		return;
	}
	$r->{d} = $r->{ifcall}->{stat};
	if(!defined $r->{srv}->{wstat}){
		respond($r, "wstat prohibited");
		return;
	}
	if($r->{d}->{type} != $Plan9::syncdir{type}){
		respond($r, "wstat -- attempt to change type");
		return;
	}
	if($r->{d}->{dev} != $Plan9::syncdir{dev}){
		respond($r, "wstat -- attempt to change dev");
		return;
	}
	if($r->{d}->{qid}->{type} != $Plan9::syncdir{qid}->{type}
	or $r->{d}->{qid}->{vers} != $Plan9::syncdir{qid}->{vers}
	or $r->{d}->{qid}->{path} != $Plan9::syncdir{qid}->{path}) {
		respond($r, "wstat -- attempt to change qid");
		return;
	}
	if($r->{d}->{muid} ne $Plan9::syncdir{muid}){
		respond($r, "wstat -- attempt to change muid");
		return;
	}
	if($r->{d}->{mode} != $Plan9::syncdir{mode} and (($r->{d}->{mode}&Plan9::DMDIR)>>24) != ($r->{fid}->{qid}->{type}&Plan9::QTDIR)){
		respond($r, "wstat -- attempt to change DMDIR bit");
		return;
	}
	&{$r->{srv}->{wstat}}($r);
}

sub rwstat {
}

sub _allocfid($$) {
	my ($srv, $fid) = @_;
	my $f;

	if(exists $srv->{fpool}->{$fid}){
		return undef;
	}

	$f = {
		srv => $srv,
		fid => $fid,
		omode => -1,
	};
	$srv->{fpool}->{$fid} = $f;
	return $f;
}

sub _lookupfid($$) {
	my ($srv, $fid) = @_;

	return $srv->{fpool}->{$fid};
}

sub _removefid($$) {
	my ($srv, $fid) = @_;
	my $f;

	$f = $srv->{fpool}->{$fid};
	delete $srv->{fpool}->{$fid};
	return $f;
}

1;

