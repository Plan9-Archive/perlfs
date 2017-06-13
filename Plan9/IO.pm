#!/usr/bin/perl
# Copyright © 2016-2017 by Yaroslav Kolomiiets
package Plan9::IO;
use Plan9;
use Symbol;
use strict;

sub readfcall(*;$) {
	my $io = Symbol::qualify_to_ref(shift, caller);
	my $n = shift;
	my ($m, $len, $a, $b, $r);

	$m = read($io, $a, 4);
	if(!defined $m){
		$@ = "read: $!";
		return undef;
	}
	if($m != 4){
		$@ = "short read";
		return undef;
	}

	$len = unpack("V", $a);
	if($len < 4 or $len > $n) {
		$@ = "bad length in 9P2000 message header";
		return undef;
	}
	$len -= 4;
	$m = read($io, $b, $len);
	if(!defined $m || $m != $len){
		$@ = "read: $!";
		return undef;
	}
	$r = Plan9::unpackfcall($a.$b);
	if(!defined $r){
		$@ = "unpackfcall: $@";
		return undef;
	}
	return $r;
}

sub writefcall(*;\%) {
	my $io = Symbol::qualify_to_ref(shift, caller);
	my $ofcall = shift;
	my ($b, $n);

	$b = Plan9::packfcall(%$ofcall);
	if(!defined $b){
		$@ = "packfcall: $@";
		return undef;
	}
	$n = syswrite($io, $b, length($b));
	if(!defined $n){
		$@ = "syswrite: $!";
		return undef;
	}
	return $n;
}

1;
