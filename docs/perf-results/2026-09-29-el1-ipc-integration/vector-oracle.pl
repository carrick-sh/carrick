use strict; use warnings;
sub case {
 my ($name,$nr,$sizes)=@_; my $fd=syscall(19,$nr==65?42:0,2048);
 my @buf=map { pack('Q',1).("x" x 24) } @$sizes;
 my $iov=''; for my $i (0..$#$sizes) { $iov.=pack('P Q',$buf[$i],$sizes->[$i]); }
 $!=0; my $r=syscall($nr,$fd,$iov,scalar @$sizes); my $err=0+$!;
 my $value="\0"x8; $!=0; my $drain=syscall(63,$fd,$value,8);
 print "$name result=$r errno=$err drain=$drain value=".unpack('Q',$value)."\n";
 syscall(57,$fd);
}
for my $nr (65,66) { for my $s ([4,4],[8,8],[16],[0,8],[4,8],[8,4],[0,0],[]) {case("nr${nr}_".join('_',@$s),$nr,$s);} }
