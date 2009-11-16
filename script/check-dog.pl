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
    my $dport = 7000 + $n;
    my $sport = 9000 + $n;
    &command("./sheep/sheep --dport $dport --sport $sport $store/$n/");
    &command("./dog/dog --mport 9876 --dport $dport --sport $sport -d");
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
&command("make install");

print("kill all sheeps and dogs\n");
foreach my $n (0..10) {
    &stop_sdog($n);
}

print("clean up $store\n");
&command("rm $store/*/*; rm /tmp/sheepdog-700*");

print("start up sdogs\n");
my $node = int(($min_node + $max_node) / 2);
foreach my $n (shuffle(0..$node - 1)) {
    &start_sdog($n);
}

my @join_node = (0..$node-1);
my @leave_node = ($node..$max_node-1);

print("make fs\n");
&command("shepherd mkfs --copies=3");
sleep(3);

my $min_epoch = 1;
my $max_epoch = 1;
my $vdi = 0;
for (;;) {
    my $op = int(rand(9));
    if ($op == 0) {
	next if (@join_node >= $max_node);

	printf("** join test **\n");

	@leave_node = shuffle(@leave_node);
	$node = pop(@leave_node);
	&start_sdog($node);
	push(@join_node, $node);
	$max_epoch++;
	sleep(5);
	&command("shepherd info -t dog -D ".(7000+$join_node[0]), 1);
    } elsif ($op == 1) { # leave
	next if (@join_node <= $min_node);

	printf("** leave test **\n");

	@join_node = shuffle(@join_node);
	$node = pop(@join_node);
	&stop_sdog($node);
	push(@leave_node, $node);
	$max_epoch++;
	sleep(5);
	&command("shepherd info -t dog -D 7000 -D ".(7000+$join_node[0]), 1);
    } elsif ($op == 2) { # create
	next if (!grep(/0/, @join_node));

	printf("** create test **\n");

	&command("qemu-img create -f sheepdog test$vdi ".int(rand(256))."G", 1);
	$vdi++;
	&command("shepherd info -t vdi -D ".(7000+$join_node[0]), 1);
    } elsif ($op == 3) { # snapshot
	next if ($vdi == 0);
	next if (!grep(/0/, @join_node));

	printf("** snapshot test **\n");

	&command("qemu-img snapshot -c name sheepdog:test".int(rand($vdi)), 1);
	&command("shepherd info -t vdi -D ".(7000+$join_node[0]), 1);
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
	&command("shepherd info -t vdi -D ".(7000+$join_node[0]), 1);
    } elsif ($op == 5) { # lock
	next if ($vdi == 0);

	printf("** lock test **\n");

	&command("shepherd info -t vm -D ".(7000+$join_node[0]), 1);
	&command("shepherd debug -o lock_vdi test".int(rand($vdi)));
	&command("shepherd info -t vm -D ".(7000+$join_node[1]), 1);
    } elsif ($op == 6) { # release
	next if ($vdi == 0);

	printf("** release test **\n");

	&command("shepherd info -t vm -D ".(7000+$join_node[0]), 1);
	&command("shepherd debug -o release_vdi test".int(rand($vdi)));
	&command("shepherd info -t vm -D ".(7000+$join_node[1]), 1);
    } elsif ($op == 7) { # update_epoch
	next if ($vdi == 0);

	printf("** epoch update test **\n");

	my $target = int(rand($vdi));
	&command("shepherd debug -o vdi_info test".$target." -D ".(7000+$join_node[0]), 1);
	&command("shepherd debug -o update_epoch ".(262144 * ($target + 1))." -D ".(7000+$join_node[1]), 1);
	&command("shepherd debug -o vdi_info test".$target." -D ".(7000+$join_node[2]), 1);
    } elsif ($op == 8) { # get_node_list

	printf("** get node list test **\n");

	my $epoch = $min_epoch + int(rand($max_epoch - $min_epoch + 1));
	&command("shepherd info -t dog -e $epoch -D 7000 -D ".(7000+$join_node[0]));
    } elsif ($op == 9) { # make fs

	printf("** make fs test **\n");

	$min_epoch = $max_epoch;
	&command("shepherd mkfs --copies=3 -D 7000 -D ".(7000+$join_node[0]));
    }
}
