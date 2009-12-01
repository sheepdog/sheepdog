#!/usr/bin/perl

use strict;

my ($store, $min_node, $max_node) = @ARGV;

$store = "/tmp/".rand(100)  unless $store;
$min_node = 3  unless $min_node;
$max_node = 5  unless $max_node;

sub command {
    my ($cmd) = @_;
    print "$cmd\n";
    system "$cmd";
}

sub start_sdog {
    my ($n) = @_;
    my $port = 7000 + $n;
    &command("./collie/collie --port $port $store/$n/ -d");
}

sub stop_sdog {
    my ($n) = @_;
    &command("./script/stop-sheepdog $n");
}

sub shuffle {
    my @list =@_;

    for my $i ( 0..$#list ) {
        my $rand=int(rand(@list));
        my $tmp=$list[$i];
        $list[$i]=$list[$rand];
        $list[$rand]=$tmp;
    }
    @list
}

print("** setup **");
&command("make clean");
&command("make");

print("kill all sheeps and dogs\n");
foreach my $n (0..10) {
    &stop_sdog($n);
}

print("clean up $store\n");
&command("rm $store/[0-9]/*");

print("start up sdogs\n");
my $node = int(($min_node + $max_node) / 2);
foreach my $n (shuffle(0..$node - 1)) {
    &start_sdog($n);
}

my @join_node = (0..$node-1);
my @leave_node = ($node..$max_node-1);

sleep(8);
print("make fs\n");
&command("shepherd mkfs --copies=3");

my $min_epoch = 1;
my $max_epoch = 1;
my $vdi = 0;
for (;;) {
    my $op = int(rand(9));
    print("op: $op\n");
    if ($op == 0) { # join
	next;
    } elsif ($op == 1) { # leave
	next;
    } elsif ($op == 2) { # create
	next if (!grep(/0/, @join_node));

	printf("** create test **\n");

	&command("qemu-img create -f sheepdog test$vdi ".int(rand(256))."G", 1);
	$vdi++;
	&command("shepherd info -t vdi -p ".(7000+$join_node[0]), 1);
    } elsif ($op == 3) { # snapshot
	next if ($vdi == 0);
	next if (!grep(/0/, @join_node));

	printf("** snapshot test **\n");

	&command("qemu-img snapshot -c name sheepdog:test".int(rand($vdi)), 1);
	&command("shepherd info -t vdi -p ".(7000+$join_node[0]), 1);
    } elsif ($op == 4) { # clone
	next if (!grep(/0/, @join_node));
	my $target_vdi;
	my $tag;
	my $list=`shepherd info -t vdi | tail -n 3`;
	if ($list=~/ : test(\d+)[^g]+g:\s+(\w+), not current/) {
	    $target_vdi = $1;
	    $tag = $2;
	} else {
	    next
	}

	printf("** clone test **\n");

	&command("qemu-img create -b sheepdog:test$target_vdi:$tag -f sheepdog test$vdi", 1);
	$vdi++;
	&command("shepherd info -t vdi -p ".(7000+$join_node[0]), 1);
    } elsif ($op == 5) { # lock
	next if ($vdi == 0);

	printf("** lock test **\n");

	&command("shepherd info -t vm -p ".(7000+$join_node[0]), 1);
	&command("shepherd debug -o lock_vdi test".int(rand($vdi)));
	&command("shepherd info -t vm -p ".(7000+$join_node[1]), 1);
    } elsif ($op == 6) { # release
	next if ($vdi == 0);

	printf("** release test **\n");

	&command("shepherd info -t vm -p ".(7000+$join_node[0]), 1);
	&command("shepherd debug -o release_vdi test".int(rand($vdi)));
	&command("shepherd info -t vm -p ".(7000+$join_node[1]), 1);
    } elsif ($op == 7) { # update_epoch
	next;
    } elsif ($op == 8) { # get_node_list

	printf("** get node list test **\n");

	my $epoch = $min_epoch + int(rand($max_epoch - $min_epoch + 1));
	&command("shepherd info -t dog -e $epoch -p ".(7000+$join_node[0]));
    } elsif ($op == 9) { # make fs
	next;
    }
}
