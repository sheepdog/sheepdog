#!/usr/bin/perl
#
# Genrate bash_completion_dog
#

use strict;

my ($program) = @ARGV;

print "#!bash\n";
print "\n";

open IN, "$program -h |" or die "cannot find $program\n";
my @help = <IN>;
close IN;

# Hash of sub command arrays.
# E.g. $subcmds{'node'} = [kill, list, info, recovery, md]
my %subcmds;

# Hash of sub sub command arrays.
# E.g. $subsubcmds{'trace graph'} = [cat, stat]
my %subsubcmds;

# Hash of option arrays.
# E.g. $opts{'node list'} = [-a, --address, -p, --port, -r, --raw, -h, --help]
my %opts;

foreach (@help) {
    if (/^  (\S+) (\S+)/) {
	my ($cmd, $subcmd) = ($1, $2);

	$subcmds{$cmd} = []  if (!defined($subcmds{$cmd}));

	push @{$subcmds{$cmd}}, $subcmd;
	$opts{"$cmd $subcmd"} = [];
	$subsubcmds{"$cmd $subcmd"} = [];

	# run sub command to get more detailed usage
	open IN, "$program $cmd $subcmd -h |";
	while (<IN>) {
	    if (/^  (-.), (--\S+)/) {
		# get options
		push @{$opts{"$cmd $subcmd"}}, $1;
		push @{$opts{"$cmd $subcmd"}}, $2;
	    } elsif (/^  ([a-z]+)/) {
		# get available subcommands
		push @{$subsubcmds{"$cmd $subcmd"}}, $1;
	    }
	}
	close IN;
    }
}

foreach my $cmd (keys %subcmds) {
    my @subcmds = @{$subcmds{$cmd}};

    print command($cmd, @subcmds);

    foreach my $subcmd (@subcmds) {
	print subcommand($cmd, $subcmd);
    }
}

print <<__EOB__;
_dog()
{
    local opts cur cmd subcmd
    opts="@{[keys %subcmds]}"
    cur="\${COMP_WORDS[COMP_CWORD]}"

    if [ \$COMP_CWORD -gt 1 ]; then
        cmd=\${COMP_WORDS[1]}
    fi

    if [ \$COMP_CWORD -gt 2 ]; then
        subcmd=\${COMP_WORDS[2]}
    fi

    case "\${cmd}" in
__EOB__

    foreach my $cmd (keys %subcmds) {
	print <<__EOB__;
        $cmd)
            _dog_$cmd \${subcmd}
            ;;
__EOB__
    }

print <<__EOB__;
        "")
            COMPREPLY=(\$( compgen -W "\${opts}" -- \${cur} ))
            ;;
        *)
            COMPREPLY=()
            ;;
    esac
}

complete -F _dog dog
__EOB__

exit 0;

# get a completion function for dog command (e.g. _dog_vdi())
sub command {
    my ($cmd, @subcmds) = @_;
    my $output;

    $output = <<__EOB__;
    _dog_${cmd}()
    {
	local opts
	opts="@subcmds"

	case "\$1" in
__EOB__

    foreach my $subcmd (@subcmds) {
	$output .= <<__EOB__;
	    $subcmd)
	        _dog_${cmd}_${subcmd}
	        ;;
__EOB__
    }

    $output .= <<__EOB__;
	    "")
	        COMPREPLY=(\$( compgen \\
	            -W "\${opts}" \\
	            -- "\${COMP_WORDS[COMP_CWORD]}" ))
	        ;;
	    *)
	        COMPREPLY=()
	        ;;
        esac
    }

__EOB__

    $output =~ s/\t/        /g;
    $output =~ s/^    //gm;

    return $output;
}

# get a completion function for dog subcommands (e.g. _dog_vdi_create())
sub subcommand {
    my ($cmd, $subcmd) = @_;
    my $output;
    my @opts = @{$opts{"$cmd $subcmd"}};
    my @subsubcmds = @{$subsubcmds{"$cmd $subcmd"}};

    $output = <<__EOB__;
    _dog_${cmd}_${subcmd}()
    {
        local cur
        cur="\${COMP_WORDS[COMP_CWORD]}"

        case "\$cur" in
            -*)
                COMPREPLY=(\${COMPREPLY[@]} \\
                    \$( compgen \\
                    -W "@opts" \\
__EOB__

    $output .= <<__EOB__;
                    -- \${cur} ))
                ;;
__EOB__

    if ($cmd eq 'vdi' && $subcmd ne 'create') {
	$output .= <<__EOB__;
            *)
                local dog="\${COMP_WORDS[0]}"
		local vdilist="\$(\${dog} vdi list -r 2>/dev/null | awk '{print \$2}')"
		COMPREPLY=(\$( compgen -W "@subsubcmds \${vdilist}" -- \${cur} ))
                ;;
__EOB__
    } else {
	$output .= <<__EOB__;
            *)
		COMPREPLY=(\$( compgen -W "@subsubcmds" -- \${cur} ))
                ;;
__EOB__
    }

    $output .= <<__EOB__;
        esac
    }

__EOB__

    $output =~ s/\t/        /g;
    $output =~ s/^    //gm;

    return $output;
}
