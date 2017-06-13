# Copyright © 2016 by Yaroslav Kolomiiets
package Plan9::Dbg;
use Plan9;

$Plan9::Srv::chatty = 1;
$Plan9::FS::chatty = 1;

sub vlongstrx($) {
	local $_ = shift;
	my ($lo, $hi);

	($lo, $hi) = ($_, 0);
	if($lo == ~0){
		$hi = ~0;
	}
	return sprintf("%.8lx%.8lx", $hi, $lo);
}

sub vlongstrd($) {
	local $_ = shift;
	my ($lo, $hi);

	($lo, $hi) = ($_, 0);
	if($lo == ~0){
		$hi = ~0;
	}
	sprintf("%lld", $hi<<32|$lo);
}

sub qidstr($) {
	local $_ = shift;
	my ($p, $t);

	$p = vlongstrx($_->{path});
	$t = qidtype($_->{type});
	return sprintf("(%s %lu %s)", $p, $_->{vers}, $t);
}

sub dirstr($) {
	my $d = shift;
	my $l;

	$l = vlongstrd($d->{length});
	return sprintf("'%s' '%s' '%s' '%s' q %s m %lo at %ld mt %ld l %s t %d d %d",
		@{$d}{qw(name uid gid muid)}, qidstr($d->{qid}),
		@{$d}{qw(mode atime mtime)}, $l, @{$d}{qw(type dev)});
}

sub qidtype($) {
	my $t = shift;
	my $s = '';

	$s .= 'd' if($t & Plan9::QTDIR);
	$s .= 'a' if($t & Plan9::QTAPPEND);
	$s .= 'l' if($t & Plan9::QTEXCL);
	$s .= 'M' if($t & Plan9::QTMOUNT);
	$s .= 'A' if($t & Plan9::QTAUTH);
	$s .= 't' if($t & Plan9::QTTMP);
	return $s;
}

sub fcallstr {
	my $f = shift;
	my ($i, $s, $nwname, $nwqid, $fntab, $fn);
	local $_;

	$fntab = {		
		&Plan9::Tversion =>	sub {
			sprintf("Tversion tag %u msize %u version '%s'", @$f{'tag','msize','version'})
		},
		&Plan9::Rversion =>	sub {
			sprintf("Rversion tag %u msize %u version '%s'", @$f{'tag','msize','version'})
		},
		&Plan9::Tauth =>	sub {
			sprintf("Tauth tag %u afid %d uname %s aname %s",
				@{$f}{'tag','afid','uname','aname'})
		},
		&Plan9::Rauth =>	sub { sprintf("Rauth tag %u aqid %s", $f->{tag}, qidstr($f->{aqid})) },
		&Plan9::Rerror =>	sub { sprintf("Rerror tag %u ename '%s'", @{$f}{'tag','ename'}) },
		&Plan9::Tflush =>	sub { sprintf("Tflush tag %u oldtag %u", @{$f}{'tag','oldtag'}) },
		&Plan9::Rflush =>	sub { sprintf("Rflush tag %u", $f->{'tag'}) },
		&Plan9::Tattach =>	sub { sprintf("Tattach tag %u fid %d afid %d uname '%s' aname '%s'",
			@{$f}{'tag','fid', 'afid','uname','aname'}) },
		&Plan9::Rattach =>	sub { sprintf("Rattach tag %u qid %s", ${$f}{tag}, qidstr($f->{qid})) },
		&Plan9::Twalk =>	sub {
			$nwname = @{$f->{wname}};
			$s = sprintf("Twalk tag %u fid %d newfid %d nwname %d",
				@{$f}{'tag','fid','newfid'}, $nwname);
			for($i=0; $i<$nwname; $i++){
				$s .= sprintf(" %d:%s", $i, $f->{wname}[$i]);
			}
			$s
		},
		&Plan9::Rwalk =>	sub {
			$nwqid = @{$f->{wqid}};
			$s = sprintf("Rwalk tag %u nwqid %d", ${$f}{tag}, $nwqid);
			for($i=0; $i<$nwqid; $i++){
				$s .= sprintf(" %d:%s", $i, qidstr($f->{wqid}[$i]));
			}
			$s
		},
		&Plan9::Topen =>	sub { sprintf("Topen tag %u fid %d mode %d", @{$f}{'tag', 'fid', 'mode'}) },
		&Plan9::Ropen =>	sub { sprintf("Ropen tag %u qid %s iounit %u", $f->{tag}, qidstr(${$f}{qid}), $f->{iounit}) },
		&Plan9::Tcreate =>	sub { sprintf("Tcreate tag %u fid %d name %s perm %o mode %d", @{$f}{'tag','fid','name','perm','mode'}) },
		&Plan9::Rcreate =>	sub { sprintf("Rcreate tag %u qid %s iounit %u", ${$f}{tag}, qidstr(${$f}{qid}), ${$f}{iounit}) },
		&Plan9::Tread =>	sub { 
sprintf("Tread tag %u fid %d offset %s count %u", @{$f}{'tag','fid'}, vlongstrd($f->{offset}), $f->{'count'}) },
		&Plan9::Rread =>	sub { sprintf("Rread tag %u count %u ...", $f->{tag}, length($f->{data})) },
		&Plan9::Twrite =>	sub { sprintf("Twrite tag %u fid %d offset %s count %u ...", @{$f}{'tag','fid'}, vlongstrd($f->{offset}), length($f->{data})) },
		&Plan9::Rwrite =>	sub { sprintf("Rwrite tag %u count %u", @{$f}{'tag','count'}) },
		&Plan9::Tclunk =>	sub { sprintf("Tclunk tag %u fid %d", @{$f}{'tag','fid'}) },
		&Plan9::Rclunk =>	sub { sprintf("Rclunk tag %u", ${$f}{tag}) },
		&Plan9::Tremove =>	sub { sprintf("Tremove tag %u fid %d", @{$f}{'tag','fid'}) },
		&Plan9::Rremove =>	sub { sprintf("Rremove tag %u", ${$f}{tag}) },
		&Plan9::Tstat =>	sub { sprintf("Tstat tag %u fid %d", @{$f}{'tag','fid'}) },
		&Plan9::Rstat =>	sub { sprintf("Rstat tag %u %s", ${$f}{tag}, dirstr($f->{stat})) },
		&Plan9::Twstat =>	sub { sprintf("Twstat tag %u %s", ${$f}{tag}, dirstr($f->{stat})) },
		&Plan9::Rwstat =>	sub { sprintf("Rwstat tag %u", ${$f}{tag}) },
	};

	$fn = $fntab->{$f->{type}};
	if(defined $fn){
		$s = &$fn($f);
	}else{
		$s = sprintf("unknown type %d", $_);
	}
	return $s;
}
1;
