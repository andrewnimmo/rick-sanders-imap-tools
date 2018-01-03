#!/usr/bin/perl

# $Header: /mhub4/sources/imap-tools/imapdump.pl,v 1.54 2015/12/04 16:38:53 rick Exp $

#######################################################################
#   Program name    imapdump.pl                                       #
#   Written by      Rick Sanders                                      #
#   Date            1/03/2008                                         #
#                                                                     #
#   Description                                                       #
#                                                                     #
#   imapdump.pl is a utility for extracting all of the mailboxes      #
#   and messages in an IMAP user's account.  When supplied with       # 
#   host/user/password information and the location of a directory    #
#   on the local system imapdump.pl will connect to the IMAP server,  #
#   extract each message from the user's account, and write it to     #
#   a file.  The result looks something like this:                    #
#                                                                     #
#     /var/backups/INBOX                                              #
#          1 2 3 4 5                                                  #
#     /var/backups/Drafts                                             #
#          1 2                                                        #
#     /var/backups/Notes/2002                                         #
#          1 2 3 4 5 6 7                                              #
#     /var/backups/Notes/2003                                         #
#          1 2 3                                                      #
#     etc etc                                                         #
#                                                                     #
#   imapdump.pl is called like this:                                  #
#      ./imapdump.pl -S host/user/password -f /var/backup             #
#                                                                     #
#   Optional arguments:                                               #
#	-d debug                                                      #
#       -I show IMAP protocol exchanges                               #
#       -L logfile                                                    #
#       -m mailbox list (dumps only the specified mailboxes, see      #
#                        the usage notes for syntax)                  #
#######################################################################

use Socket;
use IO::Socket;
use FileHandle;
use Fcntl;
use Getopt::Std;
use File::Path;
use MIME::Base64 qw(decode_base64 encode_base64);
use Encode;

#################################################################
#            Main program.                                      #
#################################################################

   init();

   if ( $users_file ) {
      @users = get_users( $users_file );
   } elsif ( $user and $pwd ) {
      push( @users, "$user|$pwd");
   } else {
      push( @users, $sourceUser );
   }

   my $pm = Parallel::ForkManager->new( $num_children ) if $num_children != -1;

   foreach $sourceUser ( @users ) {
      if ( $num_children == -1 ) {
         #  We're on Windows or the number of children has not been set
         dump_user( $sourceUser, $dir );
         summary_file( $summary_fn) if $summary_fn;
         next;
      }

      $pm->run_on_finish( sub {
      my($pid,$exit_code,$ident,$exit_signal,$core_dump,$var,$v)=@_;
         ($copied,$mbx) = split(/,/, ${$var});
         $total += $copied;
         push( @summary, "Copied $copied messages from $mbx");
      });

      $pm->start and next;

      #  This is the child process, backing up $sourceUser");

      dump_user( $sourceUser, $dir );
      if ( $summary_fn ) {
         summary_file( $summary_fn );
      }
      exit;
   }

   $pm->wait_all_children if $num_children != -1;

   Log("Done");
   exit;

sub dump_user {

my $sourceUser = shift;
my $dir        = shift;
my %DUMPED;

   $errors = $total_msgs = $total_msgs_dumped = 0;

   push( @summary, "Account accessed and dumped:  $user");
   ($user) = split(/:|\||::/, $sourceUser);
   Log("Dumping messages for $user");
   my $userdir = "$dir/$user";
   mkdir( $userdir, 0777 ) unless -d $userdir;
   if ( $no_dups ) {
      #  The user wants to make sure we only dump messages which
      #  have not been dumped before.  Use a dbm file to keep
      #  track of previously dumped messages.
      Log("Running in no-duplicates mode");

      if ( !$dbm_dir ) {
         $dbm_dir = $dir;
      }
      $dbm = $dbm_dir . '/' . $user . '/dumped';
      unless( dbmopen(%DUMPED, $dbm, 0600) ) {
        Log("Can't open $dbm: $!\n");
        exit unless $debug;
      } else {
        Log("Opened dbm file $dbm");
      }

      if ( $debug ) {
         Log("Messages previously dumped");
         while(($x,$y) = each( %DUMPED ) ) {
             Log("   $x");
         }
      }
   }

   #  Get list of all messages on the source host by Message-Id
   #
   connectToHost($sourceHost, \$conn);

   if ( $extract_attachments ) {
      $workdir = $dir . "/work";
      mkdir( $workdir, 0777 ) unless -d $workdir;
   }

   exit if !login( $sourceUser, $sourcePwd, $conn );

   if ( $summary_fn ) {
      $quota_extension = capability( $conn );
      if ( $quota_extension eq 'enabled' ) {
         Log("The server supports the IMAP QUOTA extension");
         $account_size = get_quota( $conn );
         $get_account_size = 1;
      }  elsif ( !$dont_prompt_size ) {
         print STDOUT "The server does not support the QUOTA extension\n\n";
         print STDOUT "The account size will have to be determined by examining each\n";
         print STDOUT "each message individually).  That will take longer especially\n";
         print STDOUT "if the account is large.\n\n";
         print STDOUT "Do you want to skip the account_size scan?  [Y or N]   ";
         chomp( $ans = <> );
         $ans = uc( $ans );
         $get_account_size = 0 if substr($ans, 0 , 1 ) eq 'Y';
         $get_account_size = 1 if substr($ans, 0 , 1 ) eq 'N';
      } else {
         $get_account_size = 1;
      }
   }

   @mbxs = ();
   if ( $summary_fn ) {
      $total_msgs = 0;
      @mbxs = getMailboxList($sourceUser, $conn);
      foreach $mbx ( @mbxs ) {
         $count = selectMbx( $mbx, $conn );
         $total_msgs   += $count;
         if ( $quota_extension eq 'not enabled' and $get_account_size ) {
            $bytes = get_mbx_size( $mbx, $conn );
            $account_size += $bytes;
         }
      }
      commafy( \$total_msgs );
      if ( $account_size !~ /MB/ ) {
         $account_size = sprintf( "%.2f", $account_size/1000000 );
         $account_size .= ' MB';
      }
   }

   if ( $prescan ) {
      if ( $opt_c ) {
         european_format( \$account_size );
         european_format( \$total_msgs );
         $now = get_date_european( time() );
         $elapsed = time() - $start_time;
      } else {
         $now = localtime();
         $elapsed = time() - $start_time;
      } 

      Log("-----------------------------------------------");
      Log("IMAP Dump Report");
      Log("-----------------------------------------------");
      Log("Imap_Tools: Imapdump Prescan Report");
      Log("-----------------------------------------------");
      Log("Mail server          : $this_host");
      Log("Date started         : $start");
      Log("Date completed       : $now");
      Log("Completed in         : $elapsed seconds");
      Log("User Account         : $user");
      Log("Total IMAP msgs      : $total_msgs");
      Log("Total Account size   : $account_size");
      Log("-----------------------------------------------");
      Log("Imap_Tools: End of Imapdump Prescan Report");
      Log("-----------------------------------------------");

      print SUM "-----------------------------------------------\n";
      print SUM "Imap_Tools: Imapdump Prescan Report\n";
      print SUM "-----------------------------------------------\n";
      print SUM "Date started         : $start\n";
      print SUM "Date completed       : $now\n";
      print SUM "Completed in         : $elapsed seconds\n";
      print SUM "User Account         : $user\n";
      print SUM "Total IMAP msgs      : $total_msgs\n";
      print SUM "Total Account size   : $account_size\n";
      print SUM "-----------------------------------------------\n";
      print SUM "Imap_Tools: End of Imapdump Prescan Report\n";
      print SUM "-----------------------------------------------\n";
      exit;
   }
   
   #  Get a count of all mailboxes
   @total_mbxs = getMailboxList($sourceUser, $conn, 'LIST_ALL' );
   $total_num_folders = scalar @total_mbxs;

   @mbxs = getMailboxList($sourceUser, $conn) unless @mbxs;
   $num_folders = scalar @mbxs;

   #  Exclude certain mbxs if that's what the user wants
   if ( $excludeMbxs or $excludeMbxs_regex ) {
      exclude_mbxs( \@mbxs );
   }
   $total_dumped_folders = scalar @mbxs;

   $added=$downloaded=$dump_errors=0;
   foreach $mbx ( @mbxs ) {
        Log("Dumping messages in $mbx mailbox") if $dump_flags;
        my @msgs;

        if ( $sent_after ) {
           getDatedMsgList( $mbx, $sent_after, \@msgs, $conn, 'EXAMINE' );
        } else {
           $search_list = '';
           if ( $imap_search ) {
              selectMbx( $mbx, $conn );
              getSearchList( $mbx, \$list, $imap_search, $conn );
           } 
           getMsgList( $mbx, $list, \@msgs, $conn, 'EXAMINE' );
        }

        if ( $update ) {
           #  Get a list of the messages in the dump directory by msgid           
           Log("Reading $dir/$user/$mbx");
           $count = get_msgids( "$dir/$user/$mbx", \%MSGIDS );
           Log("There are $count messages in $dir/$user/$mbx");
        }

        my $i = $#msgs + 1;
        if ( $imap_search ) {
           Log("$mbx has $i messages matching $imap_search");
        } else {
           Log("$mbx has $i messages");
        }
        my $msgnums;
        $updated = $flags_updated = $added = 0;

        foreach $msgnum ( @msgs ) {
             $fn = '';
             ($msgnum,$date,$flags,$msgid) = split(/\|/, $msgnum);
             ($fn,$oldflags) = split(/\|/, $MSGIDS{"$msgid"} );
             if ( $no_dups ) {
                #  If the user wants no duplicates and we have already
                #  dumped this message then skip it.
                if ( $DUMPED{"$msgid"} ) {
                   Log("   $msgid has already been dumped") if $debug;
                   next;
                } else {
                   Log("   Dumping msgnum $msgnum - $msgid") if $debug;
                }
             } elsif ( $update and $sync_flags and $fn ) {
                summarize_flags( \$flags );
                # ($fn,$oldflags) = split(/\|/, $MSGIDS{"$msgid"} );
                if ( $oldflags ne $flags ) {
                   Log("$fn: The flags have changed: new=$flags   old=$oldflags");
                   ($newfn) = split(/,/, $fn);
                   $newfn .=  ',' . $flags;
                   $rc = rename( $fn, $newfn );
                   $flags_updated++;
                   next;
                }  else {
                   next;
                }
             } elsif ( $update ) {
                #  Don't dump the message if it already exists in the dump directory
                if ( $MSGIDS{"$msgid"} ) {
                   Log("   $msgid exists in the dump directory") if $debug;
                   next;
                } else {
                   Log("   Dumping msgnum $msgnum  --- $msgid");
                   $updated++;
                }
             }

             $message = fetchMsg( $msgnum, $mbx, $conn );
             $downloaded_size += length( $message );
             mkpath( "$dir/$user/$mbx" ) if !-d "$dir/$user/$mbx";

             if ( $use_header_field_for_filename ) {
                $msgfile = get_header_field( $use_header_field_for_filename, \$message );
                $msgfile = $msgnum if !$msgfile;
             } else {
                $msgfile = $msgnum;
             }
             clean_filename( \$msgfile );

             $msgfile = unique( $msgfile, "$dir/$user/$mbx" );

             if ( $update ) {
                #  Make sure filename is unique
                $msgfile = unique( $msgfile, "$dir/$user/$mbx" );
             }

             if ( $include_all_flags ) {
                summarize_flags( \$flags);
                $msgfile .= ",$flags" if $flags;
             } elsif ( $include_flag and $flags =~ /Seen/i ) {
                $msgfile .= ',S';
             }

             if ( !open (M, ">$dir/$user/$mbx/$msgfile") ) {
                Log("Error opening $dir/$user/$mbx/$msgfile: $!");
                $dump_errors++;
                next;
             }
             Log("   Copying message $msgnum") if $debug;
             print M $message;
             close M;
             $added++;
             $total_msgs_dumped++;

             set_file_date( "$dir/$user/$mbx/$msgfile", $date ) if $set_file_date;

             if ( $no_dups ) {
                #  Flag it as dumped
                $DUMPED{"$msgid"} = 1;
             }

             if ( $extract_attachments ) {
                extract_attachments( $msgfile, "$dir/$user/$mbx", $workdir );
             }
 
             $msgnums .= "$msgnum ";
        }
        if ( $sync_flags and $update ) {
           Log("Flags updated $flags_updated messages in $mbx");
        }
        Log("Dumped $added messages in $mbx") if $added;

        if ( $remove_msgs ) {
           selectMbx( $mbx, $conn );
           deleteMsg( $conn, $msgnums, $mbx ) if $remove_msgs; 
           expungeMbx( $conn, $mbx )          if $remove_msgs;
        }
   }

   logout( $conn );

   #  Remove the workdir
   rmdir $workdir;

}


sub init {

   $version = 'V1.0';
   $os = $ENV{'OS'};
   $os = lc( $os );

   processArgs();

   if ($timeout eq '') { $timeout = 60; }

   #  Open the logFile
   #
   if ( $logfile ) {
      if ( !open(LOG, ">> $logfile")) {
         print STDOUT "Can't open $logfile: $!\n";
      } 
      select(LOG); $| = 1;
   }
   Log("\n$0 starting");

   #  Determine whether we have SSL support via openSSL and IO::Socket::SSL
   $ssl_installed = 1;
   eval 'use IO::Socket::SSL';
   if ( $@ ) {
      $ssl_installed = 0;
   }
   if ( $dump_flags ) {
      Log("Dumping only those messages with one of the following flags: $dump_flags");
   }

   if ( $extract_attachments ) {
      eval 'use MIME::Parser';
      if ( $@ ) {
         Log("The Perl module MIME::Parser must be installed to extract attachments.");
         exit;
      }

      Log("Attachments will be extracted");
      $workdir = $dir . '/work' if $extract_attachments;
      mkdir( $workdir, 0777 ) unless -d $workdir;
   }

   if ( $num_children and $OS =~ /Windows/i ) {
         Log("Multi-process mode is not supported on Windows");
         $num_children = -1;
   } elsif ( $num_children > 0 ) {
      eval 'use Parallel::ForkManager';
      if ( $@ ) {
         Log("In order to run multiple copy processes you must install the Parallel::ForkManager Perl module.");
         exit;
      }
   } else {
      $num_children = -1;
   }
   Log("Running in parallel mode, number of children = $num_children") if $num_children > 1;

   if ( $set_file_date ) {
      eval 'use File::Touch';
      if ( $@ ) {
         Log("You must install the Perl module File::Touch to set the dates on dumped messages");
         exit;
      }
      eval 'use Date::Parse';
      if ( $@ ) {
         Log("You must install the Perl module DateParse to set the dates on dumped messages");
         exit;
      }
   }
   Log("Running in Update mode") if $update;
   Log("Running in no-duplicates mode") if $no_dups;
   
   $start_time = time();
   if ( $opt_c ) {
      $start = get_date_european( $start_time );
   } else {
      $start = localtime();
   }
   ($this_host) = split(/\//, $opt_S);
   ($this_host) = split(/:/, $opt_S);

   if ( $summary_fn ) {
      open(SUM, ">$summary_fn");
      print SUM "IMAP Dump Report\n";
      if ( $opt_p ) {
         print SUM "-----------------------------------------------\n";
      } else {
         print SUM "---------------------------------------------------------------------------\n";
      }
      print SUM "Mail server          : $this_host \n";
   }
}

#
#  sendCommand
#
#  This subroutine formats and sends an IMAP protocol command to an
#  IMAP server on a specified connection.
#

sub sendCommand
{
    local($fd) = shift @_;
    local($cmd) = shift @_;

    print $fd "$cmd\r\n";

    Log (">> $cmd") if $showIMAP;
    
}

#
#  readResponse
#
#  This subroutine reads and formats an IMAP protocol response from an
#  IMAP server on a specified connection.
#

sub readResponse
{
    local($fd) = shift @_;

    $response = <$fd>;
    chop $response;
    $response =~ s/\r//g;
    push (@response,$response);
    if ($showIMAP) { Log ("<< $response",2); }
}

#
#  Log
#
#  This subroutine formats and writes a log message to STDERR.
#

sub Log {
 
my $str = shift;

   #  If a logile has been specified then write the output to it
   #  Otherwise write it to STDOUT

   if ( $logfile ) {
      ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime;
      if ($year < 99) { $yr = 2000; }
      else { $yr = 1900; }
      $line = sprintf ("%.2d-%.2d-%d.%.2d:%.2d:%.2d %s %s\n",
		     $mon + 1, $mday, $year + $yr, $hour, $min, $sec,$$,$str);
      print LOG "$line";
   } 
   print STDOUT "$str\n";

}

#  Make a connection to an IMAP host

sub connectToHost {

my $host = shift;
my $conn = shift;

   Log("Connecting to $host") if $debug;
   
   ($host,$port) = split(/:/, $host);
   $port = 143 unless $port;

   # We know whether to use SSL for ports 143 and 993.  For any
   # other ones we'll have to figure it out.
   $mode = sslmode( $host, $port );

   if ( $mode eq 'SSL' ) {
      unless( $ssl_installed == 1 ) {
         warn("You must have openSSL and IO::Socket::SSL installed to use an SSL connection");
         Log("You must have openSSL and IO::Socket::SSL installed to use an SSL connection");
         exit;
      }
      Log("Attempting an SSL connection") if $debug;
      $$conn = IO::Socket::SSL->new(
         Proto           => "tcp",
         SSL_verify_mode => 0x00,
         PeerAddr        => $host,
         PeerPort        => $port,
         Domain          => AF_INET,
      );

      unless ( $$conn ) {
        $error = IO::Socket::SSL::errstr();
        Log("Error connecting to $host: $error");
        exit;
      }
   } else {
      #  Non-SSL connection
      Log("Attempting a non-SSL connection") if $debug;
      $$conn = IO::Socket::INET->new(
         Proto           => "tcp",
         PeerAddr        => $host,
         PeerPort        => $port,
      );

      unless ( $$conn ) {
        Log("Error connecting to $host:$port: $@");
        warn "Error connecting to $host:$port: $@";
        exit;
      }
   } 
   Log("Connected to $host on port $port");

}

sub sslmode {

my $host = shift;
my $port = shift;
my $mode;

   #  Determine whether to make an SSL connection
   #  to the host.  Return 'SSL' if so.

   if ( $port == 143 ) {
      #  Standard non-SSL port
      return '';
   } elsif ( $port == 993 ) {
      #  Standard SSL port
      return 'SSL';
   }
      
   unless ( $ssl_installed ) {
      #  We don't have SSL installed on this machine
      return '';
   }

   #  For any other port we need to determine whether it supports SSL

   my $conn = IO::Socket::SSL->new(
         Proto           => "tcp",
         SSL_verify_mode => 0x00,
         PeerAddr        => $host,
         PeerPort        => $port,
    );

    if ( $conn ) {
       close( $conn );
       $mode = 'SSL';
    } else {
       $mode = '';
    }

   return $mode;
}

#  trim
#
#  remove leading and trailing spaces from a string
sub trim {
 
local (*string) = @_;

   $string =~ s/^\s+//;
   $string =~ s/\s+$//;

   return;
}

sub imap_login {

   # Not used

   if ( $sourceUser =~ /(.+):(.+)/ ) {
      #  An AUTHENTICATE = PLAIN login has been requested
      my $sourceUser  = $1;
      my $authuser    = $2;
      login_plain( $sourceUser, $authuser, $sourcePwd, $conn ) or exit;
   } else {
       if ( !login($sourceUser,$sourcePwd, $conn) ) {
          Log("Check your username and password");
          print STDOUT "Login failed: Check your username and password\n";
          exit;
       }
   }

}

#  login
#
#  login in at the source host with the user's name and password
#
sub login {

my $user = shift;
my $pwd  = shift;
my $conn = shift;

   if ( $user =~ /\||:/ ) {
      ($user,$pwd) = split(/\||:/, $user);
   }

   if ( uc( $method ) eq 'CRAM-MD5' ) {
      #  A CRAM-MD5 login is requested
      Log("login method $method");
      my $rc = login_cram_md5( $user, $pwd, $conn );
      return $rc;
   }

   if ( $admin_user ) {
      ($auth_user,$auth_pwd) = split(/:/, $admin_user);
      login_plain( $user, $auth_user, $auth_pwd, $conn ) or exit;
      return 1;
   }

   if ( $pwd =~ /^oauth2:(.+)/i ) {
      $token = $1;
      Log("password is an OAUTH2 token");
      login_xoauth2( $user, $token, $conn );
      return 1;
   }

   sendCommand ($conn, "1 LOGIN $user \"$pwd\"");
   while (1) {
	readResponse ( $conn );
	if ($response =~ /^1 OK/i) {
		last;
	}
	elsif ($response =~ /NO/) {
		Log ("unexpected LOGIN response: $response");
                $access_errors++;
                return 0;
	}
   }
   Log("Logged in as $user") if $debug;

   return 1;
}

#  login_plain
#
#  login in at the source host with the user's name and password.  If provided
#  with administrator credential, use them as this eliminates the need for the 
#  user's password.
#
sub login_plain {

my $user      = shift;
my $admin     = shift;
my $pwd       = shift;
my $conn      = shift;

   #  Do an AUTHENTICATE = PLAIN.  If an admin user has been provided then use it.

   if ( !$admin ) {
      # Log in as the user
      $admin = $user
   }

   $login_str = sprintf("%s\x00%s\x00%s", $user,$admin,$pwd);
   $login_str = encode_base64("$login_str", "");
   $len = length( $login_str );

   sendCommand ($conn, "1 AUTHENTICATE PLAIN $login_str" );

   my $loops;
   while (1) {
        readResponse ( $conn );
        last if $response =~ /^1 OK/;
        if ($response =~ /^1 NO|^1 BAD|^\* BYE/i) {
           Log ("unexpected LOGIN response: $response");
           exit;
        }
        $last if $loops++ > 5;
   }

   return 1;

}

#  login_xoauth2
#
#  login in at the source host with the user's name and an XOAUTH2 token.  
#
sub login_xoauth2 {

my $user      = shift;
my $token     = shift;
my $conn      = shift;

   #  Do an AUTHENTICATE = XOAUTH2 login

   $login_str = encode_base64("user=". $user ."\x01auth=Bearer ". $token ."\x01\x01", '');
   sendCommand ($conn, "1 AUTHENTICATE XOAUTH2 $login_str" );

   my $loops;
   while (1) {
        readResponse ( $conn );
        if ( $response =~ /^\+ (.+)/ ) {
           $error = decode_base64( $1 );
           Log("XOAUTH authentication as $user failed: $error");
           return 0;
        }
        last if $response =~ /^1 OK/;
        if ($response =~ /^1 NO|^1 BAD|^\* BYE|failed/i) {
           Log ("unexpected LOGIN response: $response");
           return 0;
        }
        $last if $loops++ > 5;
   }

   Log("login complete") if $debug;

   return 1;

}

sub login_cram_md5 {

my $user = shift;
my $pwd  = shift;
my $conn = shift;

   sendCommand ($conn, "1 AUTHENTICATE CRAM-MD5");
   while (1) {
        readResponse ( $conn );
        last if $response =~ /^\+/;
        if ($response =~ /^1 NO|^1 BAD|^\* BYE/i) {
           Log ("unexpected LOGIN response: $response");
           return 0;
        }
   }

   my ($challenge) = $response =~ /^\+ (.+)/;

   Log("challenge $challenge") if $debug;
   $response = cram_md5( $challenge, $user, $pwd );
   Log("response $response") if $debug;

   sendCommand ($conn, $response);
   while (1) {
        readResponse ( $conn );

        if ( $response =~ /Microsoft Exchange/i and $conn eq $dst ) {
           #  The destination is an Exchange server
           $exchange = 1;
           Log("The destination is an Exchange server");
        }

        last if $response =~ /^1 OK/i;
        if ($response =~ /^1 NO|^1 BAD|^\* BYE/i) {
           Log ("unexpected LOGIN response: $response");
           return 0;
        }
   }
   Log("Logged in as $user") if $debug;

   return 1;
}



sub cram_md5 {

my $challenge = shift;
my $user      = shift;
my $password  = shift;

eval 'use Digest::HMAC_MD5 qw(hmac_md5_hex)';
use MIME::Base64 qw(decode_base64 encode_base64);

   # Adapated from script by Paul Makepeace <http://paulm.com>, 2002-10-12
   # Takes user, key, and base-64 encoded challenge and returns base-64
   # encoded CRAM. See,
   # IMAP/POP AUTHorize Extension for Simple Challenge/Response:
   # RFC 2195 http://www.faqs.org/rfcs/rfc2195.html
   # SMTP Service Extension for Authentication:
   # RFC 2554 http://www.faqs.org/rfcs/rfc2554.html
   # Args: tim tanstaaftanstaaf PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+
   # should yield: dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw

   my $challenge_data = decode_base64($challenge);
   my $hmac_digest = hmac_md5_hex($challenge_data, $password);
   my $response = encode_base64("$user $hmac_digest");
   chomp $response;

   if ( $debug ) {
      Log("Challenge: $challenge_data");
      Log("HMAC digest: $hmac_digest");
      Log("CRAM Base64: $response");
   }

   return $response;
}


#  logout
#
#  log out from the host
#
sub logout {

my $conn = shift;

   ++$lsn;
   undef @response;
   sendCommand ($conn, "$lsn LOGOUT");
   while ( 1 ) {
	readResponse ($conn);
	if ( $response =~ /^$lsn OK/i ) {
		last;
	}
	elsif ( $response !~ /^\*/ ) {
		Log ("unexpected LOGOUT response: $response");
		last;
	}
   }
   close $conn;
   return;
}


#  getMailboxList
#
#  get a list of the user's mailboxes from the source host
#
sub getMailboxList {

my $user = shift;
my $conn = shift;
my $type = shift;
my @mbxs;
my @mailboxes;

   #  Get a list of the user's mailboxes
   #
   unless ( $type eq 'LIST_ALL' ) {
      if ( $mbxList ) {
         #  The user has supplied a list of mailboxes so only processes
         #  the ones in that list
         @mbxs = split(/,/, $mbxList);
         foreach $mbx ( @mbxs ) {
            trim( *mbx );
            push( @mailboxes, $mbx );
         }
         return @mailboxes;
      }
   }

   if ($debug) { Log("Get list of user's mailboxes",2); }

   sendCommand ($conn, "1 LIST \"\" *");
   undef @response;
   while ( 1 ) {
	readResponse ($conn);
	if ( $response =~ /^1 OK/i ) {
           last;
	}
	elsif ( $response !~ /^\*/ ) {
           Log ("unexpected response: $response");
           return 0;
	}
   }

   undef @mbxs;

   for $i (0 .. $#response) {
        $response[$i] =~ s/\s+/ /;
        if ( $response[$i] =~ /"$/ ) {
           $response[$i] =~ /\* LIST \((.*)\) "(.+)" "(.+)"/i;
           $mbx = $3;
        } elsif ( $response[$i] =~ /\* LIST \((.*)\) NIL (.+)/i ) {
           $mbx= $2;
        } else {
           $response[$i] =~ /\* LIST \((.*)\) "(.+)" (.+)/i;
           $mbx = $3;
        }
	$mbx =~ s/^\s+//;  $mbx =~ s/\s+$//;

	if ($response[$i] =~ /NOSELECT/i) {
		if ($debug) { Log("$mbx is set NOSELECT,skip it",2); }
		next;
	}
	if (($mbx =~ /^\#/) && ($user ne 'anonymous')) {
		#  Skip public mbxs unless we are migrating them
		next;
	}
	if ($mbx =~ /^\./) {
		# Skip mailboxes starting with a dot
		next;
	}
	push ( @mbxs, $mbx ) if $mbx ne '';
   }

   if ( $mbxList and $type ne 'LIST_ALL' ) {
      #  The user has supplied a list of mailboxes so only processes
      #  those
      @mbxs = split(/,/, $mbxList);
   }

   return @mbxs;
}

#  getMsgList
#
#  Get a list of the user's messages in the indicated mailbox on
#  the source host
#
sub getMsgList {

my $mailbox = shift;
my $list    = shift;
my $msgs    = shift;
my $conn    = shift;
my $mode    = shift;
my $seen;
my $empty;
my $msgnum;
my $from;
my $flags;
my $msgid;

   Log("getMsgList, list = $list") if $debug;
   $mode = 'EXAMINE' unless $mode;
   sendCommand ($conn, "1 $mode \"$mailbox\"");
   undef @response;
   $empty=0;
   $loops=0;
   while ( 1 ) {
	readResponse ( $conn );

        if ( $loops++ > 99 ) {
           Log("The IMAP server stopped responding");
           exit;
        }

	if ( $response =~ / 0 EXISTS/i ) { $empty=1; }
	if ( $response =~ /^1 OK/i ) {
		last;
	}
	elsif ( $response !~ /^\*/ ) {
		Log ("unexpected response: $response");
		return 0;
	}
   }

   if ( $list ) {
      $range = $list;
   } elsif ( $opt_R ) {
      #  Fetch this many messages (for testing)
      $range = "1:$opt_R";
   } else {
      $range = '1:*';
   }

   Log("range $range") if $debug;

   sendCommand ( $conn, "1 FETCH $range (uid flags internaldate body[header.fields (From Date Message-Id Subject)])");
   
   undef @response;
   $no_response=0;
   while ( 1 ) {
	readResponse ( $conn );
        check_response();

	if ( $response =~ /^1 OK/i ) {
		last;
	} 
        last if $response =~ /^1 NO|^1 BAD|^\* BYE/;
   }

   @msgs  = ();
   $flags = '';
   for $i (0 .. $#response) {
	last if $response[$i] =~ /^1 OK FETCH complete/i;

        if ($response[$i] =~ /FLAGS/) {
           #  Get the list of flags
           $response[$i] =~ /FLAGS \(([^\)]*)/;
           $flags = $1;
           $flags =~ s/\\Recent//;
        }

        if ( $response[$i] =~ /Message-Id: (.+)/i ) {
           $msgid = $1;
        }

        if ( $response[$i] =~ /INTERNALDATE/) {
           $response[$i] =~ /INTERNALDATE (.+) BODY/i;
           # $response[$i] =~ /INTERNALDATE "(.+)" BODY/;
           $date = $1;
           
           $date =~ /"(.+)"/;
           $date = $1;
           $date =~ s/"//g;
        }
        if ( $response[$i] =~ /^From:\s*(.+)/i) {
           $from = $1 unless $from;
        }
        if ( $response[$i] =~ /^Date:\s*(.+)/i) {
           $header_date = $1 unless $header_date;
        }

        if ( $response[$i] =~ /^Subject: (.+)/i) {
           $subject = $1 unless $subject;
        }

        # if ( $response[$i] =~ /\* (.+) [^FETCH]/ ) {
        if ( $response[$i] =~ /\* (.+) FETCH/ ) {
           ($msgnum) = split(/\s+/, $1);
        }

        if ( $response[$i] =~ /^\)/ or ( $response[$i] =~ /\)\)$/ ) ) {
           if ( $msgid eq '' ) {
              #  The message lacks a message-id so construct one.
              $header_date =~ s/\W//g;
              $subject =~ s/\W//g;
              if ( !$subject and !$from and !$subject ) {
                 Log("   message has no from/subject/date fields. Can't build dummy msgid");
              } else {
                 $msgid = "$header_date$subject$from";
                 $msgid =~ s/\s+//g;
                 $msgid =~ s/\+|\<|\>|\?|\*|"|'|\(|\)|\@|\.//g;
                 Log("   msgnum $msgnum has no msgid, built one as $msgid");
              }
           }
	   push (@$msgs,"$msgnum|$date|$flags|$msgid");
           $msgnum = $date = $flags = $msgid = '';
        }
   }

   return 1;

}

#  getDatedMsgList
#
#  Get a list of the user's messages in a mailbox on
#  the host which were sent after the specified date
#
sub getDatedMsgList {

my $mailbox = shift;
my $cutoff_date = shift;
my $msgs    = shift;
my $conn    = shift;
my $oper    = shift;
my ($seen, $empty, @list,$msgid);

    #  Get a list of messages sent after the specified date

    Log("Searching for messages after $cutoff_date");

    @list  = ();
    @$msgs = ();

    sendCommand ($conn, "1 $oper \"$mailbox\"");
    while ( 1 ) {
        readResponse ($conn);
        if ( $response =~ / EXISTS/i) {
            $response =~ /\* ([^EXISTS]*)/;
            # Log("     There are $1 messages in $mailbox");
        } elsif ( $response =~ /^1 OK/i ) {
            last;
        } elsif ( $response =~ /^1 NO/i ) {
            Log ("unexpected SELECT response: $response");
            return 0;
        } elsif ( $response !~ /^\*/ ) {
            Log ("unexpected SELECT response: $response");
            return 0;
        }
    }

    my ($date,$ts) = split(/\s+/, $cutoff_date);

    #
    #  Get list of messages sent after the reference date
    #
    Log("Get messages sent after $date") if $debug;
    $nums = "";
    $no_response=0;
    sendCommand ($conn, "1 SEARCH SINCE \"$date\"");
    while ( 1 ) {
	readResponse ($conn);
        check_response();
	if ( $response =~ /^1 OK/i ) {
	    last;
	}
	elsif ( $response =~ /^\*\s+SEARCH/i ) {
	    ($nums) = ($response =~ /^\*\s+SEARCH\s+(.*)/i);
	}
	elsif ( $response !~ /^\*/ ) {
	    Log ("unexpected SEARCH response: $response");
	    return;
	}
    }
    Log("$nums") if $debug;
    if ( $nums eq "" ) {
	Log ("     $mailbox has no messages sent before $date") if $debug;
	return;
    }
    my @number = split(/\s+/, $nums);
    $n = $#number + 1;

    $nums =~ s/\s+/ /g;
    @msgList = ();
    @msgList = split(/ /, $nums);

    if ($#msgList == -1) {
	#  No msgs in this mailbox
	return 1;
    }

    $n = $#msgList + 1;
    Log("there are $n messages after $sent_after");

@$msgs  = ();
$no_response=0;
for $num (@msgList) {

     sendCommand ( $conn, "1 FETCH $num (uid flags internaldate body[header.fields (Message-Id Date)])");
     
     undef @response;
     while ( 1 ) {
	readResponse   ( $conn );
        check_response();
	if   ( $response =~ /^1 OK/i ) {
		last;
	}   
        last if $response =~ /^1 NO|^1 BAD|^\* BYE/;
     }

     $flags = '';
     my $msgid;
     foreach $_ ( @response ) {
	last   if /^1 OK FETCH complete/i;
          if ( /FLAGS/ ) {
             #  Get the list of flags
             /FLAGS \(([^\)]*)/;
             $flags = $1;
             $flags =~ s/\\Recent//;
          }
   
          if ( /Message-Id:\s*(.+)/i ) {
             $msgid = $1;
          }

          if ( /INTERNALDATE/) {
             /INTERNALDATE (.+) BODY/i;
             $date = $1;
             $date =~ /"(.+)"/;
             $date = $1;
             $date =~ s/"//g;
             ####  next if check_cutoff_date( $date, $cutoff_date );
          }

          if ( /\* (.+) FETCH/ ) {
             ($msgnum) = split(/\s+/, $1);
          }

          if ( /^\)/ or /\)\)$/ ) {
             push (@$msgs,"$msgnum|$date|$flags|$msgid");
             $msgnum=$msgid=$date=$flags='';
          }
      }
   }

   foreach $_ ( @$msgs ) {
      Log("getDated found $_") if $debug;
   }

   return 1;
}


sub fetchMsg {

my $msgnum = shift;
my $mbx    = shift;
my $conn   = shift;
my $message;

   Log("   Fetching msg $msgnum...") if $debug;

   $no_response=0;
   sendCommand( $conn, "1 FETCH $msgnum (rfc822)");
   while (1) {
	readResponse ($conn);
        check_response();
   
	if ( $response =~ /^1 OK/i ) {
		$size = length($message);
		last;
	} 
	elsif ($response =~ /message number out of range/i) {
		Log ("Error fetching uid $uid: out of range",2);
		$stat=0;
		last;
	}
        elsif ( $response =~ /^1 NO|^1 BAD/ ) {
                Log("$response");
                return 0;
        }
	elsif ($response =~ /Bogus sequence in FETCH/i) {
		Log ("Error fetching uid $uid: Bogus sequence in FETCH",2);
		$stat=0;
		last;
	}
	elsif ( $response =~ /message could not be processed/i ) {
		Log("Message could not be processed, skipping it ($user,msgnum $msgnum,$destMbx)");
		push(@errors,"Message could not be processed, skipping it ($user,msgnum $msgnum,$destMbx)");
		$stat=0;
		last;
	}
	elsif 
	   ($response =~ /^\*\s+$msgnum\s+FETCH\s+\(.*RFC822\s+\{[0-9]+\}/i) {
		($len) = ($response =~ /^\*\s+$msgnum\s+FETCH\s+\(.*RFC822\s+\{([0-9]+)\}/i);
		$cc = 0;
		$message = "";
		while ( $cc < $len ) {
			$n = 0;
			$n = read ($conn, $segment, $len - $cc);
			if ( $n == 0 ) {
				Log ("unable to read $len bytes");
				return 0;
			}
			$message .= $segment;
			$cc += $n;
		}
	}
   }

   my $newmsg;
   if ( $os =~ /windows/i ) {
       #  Adjust the line termination characters
       foreach $_ ( split(/\r\n/, $message ) ) {
          $newmsg .= "$_\n";
       }
       $message = $newmsg;
       $newmsg = '';
    }
    

   return $message;

}


sub usage {

   print STDOUT "usage:\n";
   print STDOUT " imapdump.pl -S Host/User/Password -f <dir>\n";
   print STDOUT " <dir> is the file directory to write the message structure\n";
   print STDOUT " Optional arguments:\n";
   print STDOUT "          -F <flags>  (eg dump only messages with specified flags\n";
   print STDOUT "          -l <file of users>\n";
   print STDOUT "          -i <user>\n";
   print STDOUT "          -j <password>\n";
   print STDOUT "          -d debug\n";
   print STDOUT "          -x <extension>  File extension for dumped messages\n";
   print STDOUT "          -g  Dump message attachments as separate files\n";
   print STDOUT "          -G  Dump only message attachments not complete message or header (Used with -g)\n";
   print STDOUT "          -r remove messages after dumping them\n";
   print STDOUT "          -L logfile\n";
   print STDOUT "          -m mailbox list (eg \"Inbox, Drafts, Notes\". Default is all mailboxes)\n";
   print STDOUT "          -a <DD-MMM-YYYY> copy only messages after this date\n";
   print STDOUT "          -e exclude mailbox list (using exact matches)\n";
   print STDOUT "          -E exclude mailbox list (using regular expressions)\n";
   print STDOUT "          [-s] Include Seen/Unseen status in message filename (2454,S or 2454,U\n";
   print STDOUT "          [-z] Include all status flags in message filename (2454,DSF or 2454,SA\n";
   print STDOUT "          [-C] Include custom (nonstandard) flags in message filename, eg $SPECIAL$\n";
   print STDOUT "          [-u] Don't dump messages already dumped\n";
   print STDOUT "          [-D <dbm directory] Directory to put dbm file, used with -u argument\n";
   print STDOUT "          [-U] Don't dump message if it already exists in the dump directory\n";
   print STDOUT "          [-X <header field>]  Dump filename based on the selected header field, eg Subject\n";
   print STDOUT "          [-Y] set the date on the dump files based on the Date: field in the header\n";
   print STDOUT "          [-Z <IMAP SEARCH filter>]  Select msgs based on an IMAP search filter\n";
   print STDOUT "          [-N] Don't worry about making dump msgfilenames unique, just write them\n";
   print STDOUT "          [-T <summary filename>] Write a summary report to logfile and summary file \n";
   print STDOUT "          [-q] Don't prompt whether to calculate account size\n";
   print STDOUT "          [-c] European-style decimal point (comma instead of period)\n";
   print STDOUT "          To use the CRAM-MD5 login method add /CRAM-MD5 like this:  -S Host/User/Password/CRAM-MD5\n";
   exit;

}

sub processArgs {

   if ( !getopts( "dS:L:m:hf:F:Ix:ra:uD:Ue:E:A:sgR:l:n:GwzCX:YZ:N:i:j:T:qcp" ) ) {
      usage();
   }

   if ( $opt_S =~ /\\/ ) {
      @backslashes = split(/\\/, $opt_S);
      $num_backslashes = scalar @backslashes;
      if ( $num_backslashes == 2 ) {
         ($sourceHost, $sourceUser, $sourcePwd, $method ) = split(/\//, $opt_S);
      } else {
         ($sourceHost, $sourceUser, $sourcePwd, $method ) = split(/\\/, $opt_S);
      }
   } else {
      ($sourceHost, $sourceUser, $sourcePwd, $method ) = split(/\//, $opt_S);
   }

   $method = 'CRAM-MD5' if $opt_S =~ /CRAM-MD5/i;
   $sourceHost =~ s/\/CRAM-MD5//i;

   $mbxList      = $opt_m;
   $logfile      = $opt_L;
   $dir          = $opt_f;
   $extension    = $opt_x;
   $dump_flags   = $opt_F;
   $users_file   = $opt_l;
   $num_children = $opt_n;
   $user         = $opt_i;
   $pwd          = $opt_j;
   $remove_msgs  = 1 if $opt_r;
   $debug    = 1 if $opt_d;
   $showIMAP = 1 if $opt_I;
   $no_dups  = 1 if $opt_u;
   $update   = 1 if $opt_U;
   $prescan  = 1 if $opt_p;
   $dont_make_unique_filename = 1 if $opt_N;
   $set_file_date = 1 if $opt_Y;
   $extract_attachments = 1 if $opt_g;
   $extract_only_attachments = 1 if $opt_G;
   $sent_after = $opt_a;
   $dbm_dir    = $opt_D;
   $excludeMbxs       = $opt_e;
   $excludeMbxs_regex = $opt_E;
   $admin_user        = $opt_A;
   $include_flag      = $opt_s;
   $sync_flags        = $opt_w;
   $imap_search       = $opt_Z;
   $summary_fn        = $opt_T;
   $dont_prompt_size  = $opt_q;
   $include_custom_flags = 1 if $opt_C;
   $use_header_field_for_filename = $opt_X;

   if ( !$dir ) {
      print "You must specify the file directory where messages will\n";
      print "be written using the -f argument.\n\n";
      usage();
      exit;
   }

   if ( $sent_after ) {
      convert_date( \$sent_after );
      validate_date( $sent_after ) if $sent_after;
   }

   mkpath( "$dir" ) if !-d "$dir";

   if ( !-d $dir ) {
      print "Fatal Error: $dir does not exist\n";
      exit;
   }

   if ( $dump_flags ) {
      foreach my $flag ( split(/,/, $dump_flags) ) {
          $flag = ucfirst( lc($flag) );
          $flag = 'Seen'   if $flag eq 'Read';
          $flag = 'Unseen' if $flag eq 'Unread';
          $dump_flags{$flag} = 1;
      }
   }

   if ( $extension ) {
      $extension = '.' . $extension unless $extension =~ /^\./;
   }

   $get_account_size = substr($get_account_size,0,1);
   if ( uc($get_account_size) eq 'Y' ) {
      $get_account_size = 1;
   } else {
      $get_account_size = 0;
   }
   usage() if $opt_h;

}

sub findMsg {

my $conn  = shift;
my $msgid = shift;
my $mbx   = shift;
my $msgnum;

   Log("EXAMINE $mbx") if $debug;
   sendCommand ( $conn, "1 EXAMINE \"$mbx\"");
   while (1) {
	readResponse ($conn);
	last if $response =~ /^1 OK/;
   }

   Log("Search for $msgid") if $debug;
   sendCommand ( $conn, "1 SEARCH header Message-Id \"$msgid\"");
   while (1) {
	readResponse ($conn);
	if ( $response =~ /\* SEARCH /i ) {
	   ($dmy, $msgnum) = split(/\* SEARCH /i, $response);
	   ($msgnum) = split(/ /, $msgnum);
	}

	last if $response =~ /^1 OK/;
	last if $response =~ /complete/i;
   }

   return $msgnum;
}

sub deleteMsg {

my $conn    = shift;
my $msgnums = shift;
my $mbx     = shift;
my $rc;

   $msgnums =~ s/\s+$//;

   foreach my $msgnum ( split(/\s+/, $msgnums) ) {
      sendCommand ( $conn, "1 STORE $msgnum +FLAGS (\\Deleted)");
      while (1) {
        readResponse ($conn);
        if ( $response =~ /^1 OK/i ) {
	   $rc = 1;
	   Log("   Marked msgnum $msgnum for delete");
	   last;
	}

	if ( $response =~ /^1 BAD|^1 NO/i ) {
	   Log("Error setting \\Deleted flag for msg $msgnum: $response");
	   $rc = 0;
	   last;
	}
      }
   }

   return $rc;
}


sub expungeMbx {

my $conn  = shift;
my $mbx   = shift;

   Log("SELECT $mbx") if $debug;
   sendCommand ( $conn, "1 SELECT \"$mbx\"");
   while (1) {
        readResponse ($conn);
        last if $response =~ /^1 OK/;

	if ( $response =~ /^1 NO|^1 BAD/i ) {
	   Log("Error selecting mailbox $mbx: $response");
	   last;
	}
   }

   sendCommand ( $conn, "1 EXPUNGE");
   while (1) {
        readResponse ($conn);
        last if $response =~ /^1 OK/;

	if ( $response =~ /^1 BAD|^1 NO/i ) {
	   print "Error expunging messages: $response\n";
	   last;
	}
   }

}

sub flags_ok {

my $flags = shift;
my $ok = 0;

   #  If the user has specified that only messages with
   #  certain flags be dumped then honor his request.

   return 1 unless %dump_flags;

   $flags =~ s/\\//g;
   Log("flags $flags") if $debug;
   foreach $flag ( split(/\s+/, $flags) ) {
      $flag = ucfirst( lc($flag) );
      $ok = 1 if $dump_flags{$flag};
   }

   #  Special case for Unseen messages for which there isn't a 
   #  standard flag.  
   if ( $dump_flags{Unseen} ) {
      #  Unseen messages should be dumped too.
      $ok = 1 unless $flags =~ /Seen/;
   }

   return $ok;

}

sub validate_date {

my $date = shift;
my $invalid;

   #  Make sure the "after" date is in DD-MMM-YYYY format

   my ($day,$month,$year) = split(/-/, $date);
   $invalid = 1 unless ( $day > 0 and $day < 32 );
   $invalid = 1 unless $month =~ /Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec/i;
   $invalid = 1 unless $year > 1900 and $year < 2999;
   if ( $invalid ) {
      Log("The 'Sent after' date $date must be in DD-MMM-YYYY format");
      exit;
   }
}

sub get_msgids {

my $dir = shift;
my $msgids = shift;
my $i;
my $progress = 100;
my $count = 0;
my $msgid;

   #  Build a list of the messageIDs for the messages in the requested directory

   %$msgids = ();

   return 0 if !-e $dir;   # No such directory

   if ( !opendir D, $dir ) {
      Log("Error opening $dir: $!");
      return 0;
   }
   my @files = readdir( D );
   closedir D;

   $count = scalar @files;
   $count = $count - 2;

   foreach $_ ( @files ) {
      next if /^\./;
      $fn = "$dir/$_";
      next if -d $fn;   #  Skip directories
      $i++;
      Log("fn $fn") if $debug;
      ($filename,$flags) = split(/,/, $fn);
      if ( !open(MSG, "<$fn" ) ) {
         Log("Error opening $fn: $!");
         next;
      }
      $msgid = '';
      while( <MSG> ) {
         chomp;
         s/\r$|\m$//g;
         if (/^Subject:\s+(.+)/i ) {
            $subject = $1 unless $subject;
         }
         if (/^From:\s+(.+)/i ) {
            $from = $1 unless $from;
         }
         if (/^Date:\s+(.+)/i ) {
            $header_date = $1 unless $header_date;
         }

         if (/^Message-ID:\s+(.+)/i ) {
            $msgid =~ s/\+|\<|\>|\?|\*|"|'|\(|\)|\@|\.//g;
            $$msgids{"$1"} = "$fn|$flags";
            $msgid = 1;
            if ( !$msgid ) {
               #  Wrapped to next line
               chomp( $msgid = <MSG> );
               $msgid =~ s/\r$|\m$//g;
            }
         }
         last if $_ eq '';     # End of header
     }
     close MSG;

     if ( !$msgid ) {
        #  The message lacks a message-id so construct one.
        $header_date =~ s/\W//g;
        $subject =~ s/\W//g;
        $msgid = "$header_date$subject$from";
        $msgid =~ s/\s+//g;
        $msgid =~ s/\+|\<|\>|\?|\*|"|'|\(|\)|\@|\.//g;
        Log("msgnum $msgnum has no msgid, built one as $msgid") if $debug;
        $$msgids{"$msgid"} = "$fn|$flags";
     }

     if ( $i/$progress == int($i/$progress) ) { Log("   $i messages read so far"); }
   }

   return $count;
}

sub unique {

my $fn  = shift;
my $dir = shift;
my @letters = qw( a b c d e f g h i j k l m n o p q r s t u v w x y z );
my @numbers;

   for $i ( 0 .. 1024 ) {
      push( @numbers, $i );
   }
   #  Generate a filename which is unique in the directory

   $fn .= $extension if $extension;

   return $fn if !-e "$dir/$fn";
   return $fn if $dont_make_unique_filename;

   #  A file with this name exists 

   my $new;
   my $number;

   $fn =~ s/$extension$// if $extension;
   foreach $number ( @numbers ) {
      $i = $number;
      $new = $fn . '.' . $number;
      $new .= $extension if $extension;
      last if !-e "$dir/$new";
   }

   return $new;

}

#  exclude_mbxs
#
#  Exclude certain mailboxes from the list if the user has provided an
#  exclude list of complete mailbox names with the -e argument.  He may 
#  also supply a list of regular expressions with the -E argument
#  which we will process separately.

sub exclude_mbxs {

my $mbxs = shift;
my @new_list;
my %exclude;
my (@regex_excludes,@final_list);

   #  Do the exact matches first
   if ( $excludeMbxs ) {
      foreach my $exclude ( split(/,/, $excludeMbxs ) ) {
         $exclude{"$exclude"} = 1;
      }
      foreach my $mbx ( @$mbxs ) {
         next if $exclude{"$mbx"};
         push( @new_list, $mbx );
      }
      @$mbxs = @new_list;
   }

   #  Next do the regular expressions if any
   my %excludes;
   @new_list = ();
   if ( $excludeMbxs_regex ) {
      my @regex_excludes;
      foreach $_ ( split(/,/, $excludeMbxs_regex ) ) {
         push( @regex_excludes, $_ );
      }
      foreach my $mbx ( @$mbxs ) {
         foreach $_ ( @regex_excludes ) {
             if ( $mbx =~ /$_/ ) {
                $excludes{"$mbx"} = 1;
             }
         }
      }
      foreach my $mbx ( @$mbxs ) {
         push( @new_list, $mbx ) unless $excludes{"$mbx"};
      }
      @$mbxs = @new_list;
   }

   @new_list = ();

}

sub selectMbx {

my $mbx = shift;
my $conn = shift;
my $msgcount = $bytes = 0;

   #  select the mailbox
   sendCommand( $conn, "1 SELECT \"$mbx\"");
   while ( 1 ) {
      readResponse( $conn );
      if ( $response =~ /^1 OK/i ) {
         last;
      } elsif ( $response =~ /\* (.+) EXISTS/ ) {
         $msgcount = $1;
      } elsif ( $response =~ /^1 NO|^1 BAD|^\* BYE/i ) {
         Log("Unexpected response to SELECT $mbx command: $response");
         last;
      }
   }

   return $msgcount;
}

sub get_mbx_size {

my $mbx  = shift;
my $conn = shift;

   #  Calculate the size of a mailbox by fetching RFC822.SIZE for each
   #  message

   getMsgList( $mbx, $list, \@msgs, $conn, 'EXAMINE' );
      
   foreach $_ ( @msgs ) {
      ($msgnum) = split(/\|/, $_);
      sendCommand( $conn, "1 FETCH $msgnum (rfc822.size)");
      while (1 ) {
         readResponse ($conn);
         last if $response =~ /^1 OK|^1 NO|^1 BAD|^1 BYE/;
         if ( $response =~ /RFC822.SIZE/i ) {
            my @terms = split(/\s+/, $response ); 
            $size = $terms[$#terms];
            $size =~ s/\)//;
            $bytes += $size;
         }
      }
   }

   return $bytes;

}

sub reconnect {

   #  The IMAP server has dropped our session or stopped responding for some reason.
   #  Re-establish the session and continue if we can

   $number_of_reconnects++;
   if ( $number_of_reconnects > 25 ) {
      #  That's enough.  Declare a fatal error and give up.
      Log("FATAL ERROR:  Number of reconnects exceeded 25.  Exiting.");
      exit;
   }

   Log("Reconnecting...");
   sleep 30;

   connectToHost($sourceHost, \$conn);
   login();
   selectMbx( $mbx, $conn );

   #  We now return you to the previously scheduled programming already in progress
}

sub check_response {

   #  If the server has stopped responding call the reconnect() routine

   if ( $response eq '' ) {
      $no_response++;
   } else {
      $no_response = 0;
   }

   if ( $no_response > 99 ) {
      Log("The IMAP server has stopped responding");
      reconnect();
   }

}

sub extract_attachments {

my $msgfn   = shift;
my $dir     = shift;
my $workdir = shift;

   #  Extract all attachments 

   Log("msgfn $msgfn") if $debug;

   $msgfn = $dir . '/' . $msgfn;

   #  Get the message header and write it out to a file
   open(H, "<$msgfn");
   $header = '';
   while( <H> ) {
       chomp;
       $header .= "$_\n";
       last if length( $_ ) == 1;    # end of the header
   }
   close H;

   unless( $extract_only_attachments ) {
      #  Write the header to a file unless the user only wants attachments
      my $header_fn = "$msgfn" . ".header";
      open(H, ">$header_fn");
      print H "$header\n";
      close H;
   }

   parseMsg( $msgfn, $dir, $workdir );

   if ( $extract_only_attachments ) {
      #  The user wants the attachments but not the complete file or 
      #  the header file
      unlink $msgfn;
   }

}

sub parseMsg {

my $msgfn   = shift;
my $dir     = shift;
my $workdir = shift;

   #  This routine dumps the message parts to files and returns
   #  the filenames 

   #  Remove any existing files from the workdir
   opendir D, $workdir;
   my @files = readdir( D );
   closedir D;
   foreach $_ ( @files ) {
      next if /^\./;
      $fn = "$workdir/$_";
      unlink $fn if -e $fn;
   }

   my @terms = split(/\//, $msgfn );
   my $prefix = $terms[$#terms];
   Log("prefix $prefix") if $debug;

   my $parser = new MIME::Parser;

   $parser->extract_nested_messages(0);    
   $parser->output_dir( $workdir );

   # Read the MIME message and parse it.
   $entity = $parser->parse_open( $msgfn );
   $entity = $parser->parse_data( $msgfn );

   save_attachments( $dir, $workdir, $prefix );
}

sub save_attachments {

my $dir     = shift;
my $workdir = shift;
my $prefix  = shift;

   #  Apply the prefix to attachment names and move the attachments into
   #  the dump directory

   opendir D, $workdir;
   my @files = readdir( D );
   closedir D;
   my $i = 0;
   foreach $_ ( @files ) {
      next if /^\./;
      $i++;
      $filename = $_;
      if ( $filename =~ /msg-(.+)-(.+).txt/ ) {
         #  Unnamed attachment is given a random name by the parser.
         #  Rename it so we don't get dups each time we run
         $old = "$workdir/$filename";
         $new = "$workdir/attachment" . '-' . "$i.txt";
         $rc = rename( $old, $new );
         $old = $workdir . '/' . $msg . 'attachment-' . $i . ".txt";
         $new = "$dir/$prefix." . 'attachment-' . $i . ".txt";
      } else {
         $old = "$workdir/$_";
         $new = "$dir/$prefix.$_";
         $i--;
      }

      #  Move it into the dump directory
      $rc = rename( $old, $new );

      if ( !$rc ) {
         Log("Error moving $old to $new:  $!");
      }
      unlink $old if -e $old;
   }

}

sub get_users {

my $dir = shift;

   #  Build the list of users to be backed up from the users_list file

   if ( !-e $users_file ) {
      print "$users_file does not exist\n";
      exit;
   }
   if ( !open(U, "<$users_file" ) ) {
      print "Can't open $users_file: $!\n";
      exit;
   }

   while( <U> ){
      chomp;
      s/^\s+//g;
      next if /^#/;
      push( @users, $_ );
   }
   close U;

   return @users;

}

sub create_user_dir {

my $user = shift;
my $status = 1;

   #  Create a subdirectory this user's messages

   print STDOUT "user $user\n";
   print STDOUT "dir  $dir\n";

   mkdir ( "$dir/$user", 0644 );

   unless ( -d "$dir/$user" ) {
      Log("Unable to create $dir/$user: $!");
      return 0;
   }

   return $status;
}

sub summarize_flags {

my $flags = shift;

   #  Turn a list of IMAP flags into a list of single character flags

   my $FLAGS = $$flags;
   $$flags = '';
   foreach $_ ( split(/\s+/, $FLAGS ) ) {
      s/DRAFT/draft/i;
      if ( /^\\/ ) {
         Log("standard flag $_") if $debug;
         $$flags .= substr($_,1,1);
      } elsif ( /^\$/ ) {
         Log("custom flag $_") if $debug;
         $$flags .= $_ . '$' if $include_custom_flags;
      }
   }
   Log("flags $$flags") if $debug;

}

sub get_header_field {

my $field = shift;
my $message = shift;
my $value;

   #  Return the value of the requested header field
   #  Convert it from MIME-Header encoding to binary if necessary

   if ( $os =~ /windows/i ) {
      $terminator = '\n' 
   } else {
      $terminator = '\r\n';
   }

   foreach $_ ( split(/$terminator/, $$message )  ) {
      chomp;
      last if length( $_) == 1;  #  End of the header
      ($kw,$value) = split(/:\s+/, $_, 2 );
         
      if ( lc( $field ) eq lc( $kw ) ) {
         $value  = Encode::decode("MIME-Header", $value );
         return $value if isAscii( $value );

         $tmpfile = "imapdump.tmp.$$";
         open(MM, ">", $tmpfile );
         print MM "$value\n";
         close MM;

         open(MM, "<", $tmpfile);
         $string = <MM>;
         chomp $string;
         close MM;
         unlink $tmpfile if -e $tmpfile;

         last;
      }
   }
   
   return $string;

}

sub set_file_date {

my $msgfn     = shift;
my $date = shift;

   #  Set the date on the msgfile that we dumped to the date in the message header

   Log("set_date for $msgfn, date = $date") if $debug;
   $date =~ s/-/ /g;
   if ( $date =~ /\(/ ) {
      $date =~ s/\s*\((.+)\)//;
   }

   my $epoch;
   $epoch = str2time( $date );
   Log("Converted $date to epoch time:  $epoch") if $debug;
   if ( $epoch eq '' ) {
      Log("Bad date $date. Date not set for $msgfn");
      $errors++;
   } else {
      Log("$msgfn:  $date ($epoch)") if $debug;
      my $ref = File::Touch->new( mtime => $epoch, no_create =>1 );
      $count = $ref->touch( $msgfn );
      if ( !$count ) {
         Log("Error setting the date on $msgfn");
      } else {
         $date_set++;
         if ( $debug ) {
            Log("Date set on $count message(s)");
            my @info = stat( $msgfn );
            $new_date = $info[9];
            $new_date = localtime( $new_date );
            Log("New date on $msgfn = $new_date ");
           
         }
      }
   }

}

sub isAscii {

my $str = shift;
my $ascii = 1;

   #  Determine whether a string contains non-ASCII characters

   my $test = $str;
   $test=~s/\P{IsASCII}/?/g;
   $ascii = 0 unless $test eq $str;

   return $ascii;

}

sub clean_filename {

my $fn = shift;

   #  Certain characters are not permitted in filenames by the operating system
   #  so we will replace them by underscores

   if ( $os =~ /windows/i ) {
      $$fn =~ s/[\/\\:\*\?"\<\>\|]/_/g;
   } else {
      $$fn =~ s/[\/]/_/g;
   }

}

sub getSearchList {

my $mbx    = shift;
my $list   = shift;
my $search = shift;
my $conn   = shift;

   #  Get a list of msgs identified by the IMAP Search expression

   $$list = '';

   Log("search $search") if $debug;
   sendCommand ($conn, "1 SEARCH $search");
   while (1) {
        readResponse ( $conn );
        last if $response =~ /^1 OK/i;
        exit if $response =~ /^1 BYE/i;
        if ($response =~ /^1 NO|^1 BAD/) {
              Log ("unexpected SEARCH response: $response");
              return 0;
        }
        if ( $response =~ /^\* SEARCH (.+)/ ) {
           $$list = $1;
           $$list =~ s/\s+/,/g;
           Log("Matching messages $$list") if $debug;
        }
   }

}

sub commafy {

my $number = shift;

   $_ = $$number;
   1 while s/^([-+]?\d+)(\d{3})/$1,$2/;

   $$number = $_;

}

sub summary_file {

my $summary_fn = shift;

   Log("Writing summary file $summary_fn");

   $now = localtime();
   $now_time = time();
   $elapsed = $now_time - $start_time;
   $elapsed = 1 if $elapsed == 0;

   $rate = $downloaded_size/$elapsed;

   $downloaded_size = sprintf( "%.2f", $downloaded_size/1000000 );
   $rate = sprintf( "%.2f", 8 * $rate/1000000 );

   commafy( \$total_msgs );
   commafy( \$total_msgs_dumped );
   commafy( \$downloaded_size );
   commafy( \$rate );

   $account_size = 'Unknown' if !$get_account_size;
   if ( $opt_c ) {
      #  European-style decimal points 
      european_format( \$account_size );
      european_format( \$rate );
      european_format( \$total_msgs );
      european_format( \$total_msgs_dumped );
      european_format( \$downloaded_size );
      $now = get_date_european( time() );
   }

   $dump_folder = "$dir/$user";
   $dump_folder =~ s/\//\\/g if $os =~ /Windows/i;
   $dump_folder =~ s/\\\\/\\/g;

   print SUM "---------------------------------------------------------------------------\n";
   print SUM "Date started         : $start\n";
   print SUM "Date completed       : $now\n";
   print SUM "Completed in         : $elapsed seconds\n";
   print SUM "User Account         : $user\n";
   print SUM "Dump folder          : $dump_folder\n";
   print SUM "...........................................................................\n";
   print SUM "Total IMAP folders   : $total_num_folders\n";
   print SUM "Total IMAP msgs      : $total_msgs\n";
   print SUM "Total dumped folders : $total_dumped_folders\n";
   print SUM "Total dumped msgs    : $total_msgs_dumped\n";
   print SUM "Total Account size   : $account_size\n";
   print SUM "Total Size downloaded: $downloaded_size MB \n";
   print SUM "Errors               : $dump_errors\n";
   print SUM "Transfer rate        : $rate Megabits/sec\n";
   print SUM "---------------------------------------------------------------------------\n";
   print SUM "Imap_Tools: End of Imapdump Report\n";
   print SUM "---------------------------------------------------------------------------\n";

   Log("---------------------------------------------------------------------------");
   Log("IMAP Dump Report");
   Log("---------------------------------------------------------------------------");
   Log("Date started         : $start");
   Log("Date completed       : $now");
   Log("Completed in         : $elapsed seconds");
   Log("User Account         : $user");
   Log("Dump folder          : $dump_folder ");
   Log("...........................................................................");
   Log("Total IMAP folders   : $total_num_folders");
   Log("Total IMAP msgs      : $total_msgs");
   Log("Total dumped folders : $total_dumped_folders");
   Log("Total dumped msgs    : $total_msgs_dumped");
   Log("Total Account size   : $account_size");
   Log("Total Size downloaded: $downloaded_size MB ");
   Log("Errors               : $dump_errors");
   Log("Transfer rate        : $rate Megabits/sec");
   Log("---------------------------------------------------------------------------");
   Log("Imap_Tools: End of Imapdump Report");
   Log("---------------------------------------------------------------------------");

}

sub convert_date {

my $date = shift;
my @months = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );
my $time = time();

   #  If the argument is a number of days compose a date in DD-MMM-YYYY format

   return if $$date =~ /jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec/i;

   my ($sec,$min,$hr,$mday,$mon,$year,$wday,$yday,$isdst) =
          localtime( $time - $$date*86400 );
   $month = $months[$mon];
   $$date = sprintf( "%02d-%03s-%04d", $mday, $month, ($year+1900) );
   
}

sub get_quota {

my $conn = shift;

   sendCommand ($conn, "1 getquotaroot \"Inbox\"");
   while (1) {
        readResponse ( $conn );
        if ( $response =~ /\(STORAGE (.+) (.+)\)/i ) {
           $quota = $1;
        }
        if ( $response =~ /^1 OK no quota|OK GETQUOTAROOT Ok/i ) {
           #  QUOTA is supported but quotas are not set
           $quota = '';
           #  QUOTA is supported but quotas are not set
           $quota = '';
        }
        last if $response =~ /^1 OK/i;
        if ($response =~ /^1 NO|^1 BAD/i) {
           print "Unexpected response: $response\n";
           last;
        }
   }

   #  Normalize to MB
   if ( $quota ) {
      $quota = sprintf( "%.2f", $quota/1000 );
      $quota .= ' MB';
   } else {
      $quota = 'Account size not available (GETQUOTAROOT not supported by the server)';
   }

   return $quota;
}

sub capability {

my $conn = shift;
my @response;
my $capability;
my $quota_ext = 'not enabled';

   sendCommand ($conn, "1 CAPABILITY");
   while (1) {
        readResponse ( $conn );
        $capability = $response if $response =~ /\* CAPABILITY/i;
        last if $response =~ /^1 OK/i;
        if ($response =~ /^1 NO|^1 BAD/i) {
           print "Unexpected response: $response\n";
           return 0;
        }
   }

   $quota_ext = 'enabled' if $capability =~ / QUOTA\s*/i;

   return $quota_ext;

}

sub european_format {

my $number = shift;
my $MB;

   #  Replace ',' with '.' and '.' with ','
   #  to make format the number in the European style

   if ( $$number !~ /,/ ) {
      #  Commafy it first
      my ($integer,$decimal) = split(/\./, $$number );
      $MB = 1 if $$number =~ /MB/;
      $decimal =~ s/\s+MB//;
      commafy( \$integer );
      $$number = $integer . '.' . $decimal;
      $$number .= ' MB' if $MB;
   }
   $$number =~ s/\./DOT/g;
   $$number =~ s/,/COMMA/g;

   $$number =~ s/COMMA/./g;
   $$number =~ s/DOT/,/g;

   $$number =~ s/,$//g;
}

sub get_date_european {

my $seconds = shift;
my $time = time();
my @months = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );

   # Get a date in European format ( DD-MM-YYYY hr:min:sec )

   my ($sec,$min,$hr,$mday,$mon,$year,$wday,$yday,$isdst) =
          localtime( $seconds );
   $date = sprintf( "%02d-%02s-%04d %02d:%02d:%02d", $mday, $mon+1, ($year+1900), $hr, $min, $sec );

   return $date;
}

