#!/usr/bin/perl

# $Header: /mhub4/sources/imap-tools/imapPing.pl,v 1.5 2015/12/05 14:57:32 rick Exp $

############################################################################
#   Program   imapPing.pl                                                  #
#   Date      20 January 2008                                              #
#                                                                          #
#   Description                                                            #
#                                                                          #
#   This script performs some basic IMAP operations on a user's            #
#   account and displays the time as each one is executed.  The            #
#   operations are:                                                        #
#           1.  Connect to the IMAP server                                 #
#           2.  Log in with the user's name and password                   #
#           3.  Get a list of mailboxes in the user's account              #
#           4.  Select the INBOX                                           #
#           5.  Get a list of messages in the INBOX                        #
#           6.  Log off the server                                         #
#                                                                          #
# Usage: imapPing.pl -h <host> -u <user> -p <password>                     #
#                                                                          #
############################################################################
# Copyright (c) 2008 Rick Sanders <rfs9999@earthlink.net>                  #
#                                                                          #
# Permission to use, copy, modify, and distribute this software for any    #
# purpose with or without fee is hereby granted, provided that the above   #
# copyright notice and this permission notice appear in all copies.        #
#                                                                          #
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES #
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF         #
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR  #
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES   #
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN    #
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF  #
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.           #
############################################################################

use Getopt::Std;
use Socket;
use FileHandle;
use Fcntl;
use IO::Socket;
use MIME::Base64 qw(encode_base64 decode_base64);

   init();
   ($host,$user,$pwd) = getArgs(); 

   print STDOUT pack( "A35 A10", "Connecting to $host", getTime() );
   connectToHost( $host, \$conn );

   print STDOUT pack( "A35 A10","Logging in as $user", getTime() );
   login( $user,$pwd, $conn );

   print STDOUT pack( "A35 A10","Get list of mailboxes", getTime() );
   getMailboxList( $conn );

   print STDOUT pack( "A35 A10","Selecting the INBOX", getTime() );
   selectMbx( 'INBOX', $conn ) if $rc;

   print STDOUT pack( "A35 A10","Get list of msgs in INBOX", getTime() );
   getMsgList( 'INBOX', $conn );

   print STDOUT pack( "A35 A10","Logging out", getTime() );
   logout( $conn );

   print STDOUT pack( "A35 A10","Done", getTime() );
   
   exit;
   
   exit 1;


sub init {

   #  Determine whether we have SSL support via openSSL and IO::Socket::SSL
   $ssl_installed = 1;
   eval 'use IO::Socket::SSL';
   if ( $@ ) {
      $ssl_installed = 0;
   }

   getTime();
   $debug = 1;
}

sub getTime {

   ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime;
   if ($year < 99) { $yr = 2000; }
   else { $yr = 1900; }
   $date = sprintf ("%.2d-%.2d-%d.%.2d:%.2d:%.2d \n",
		$mon+1,$mday,$year+$yr,$hour,$min,$sec);
   $time = sprintf ("%.2d:%.2d:%.2d \n",$hour,$min,$sec);

   return $time;
}

sub getArgs { 

   getopts( "h:u:p:A:I" );
   $host = $opt_h;
   $user = $opt_u;
   $pwd  = $opt_p;
   $admin_user = $opt_A;
   $showIMAP = 1 if $opt_I;
print "opt_h $opt_h\n";
print "opt_p $opt_p\n";
print "opt_u $opt_u\n";

   $method = 'CRAM-MD5' if $opt_h =~ /CRAM-MD5/i;
   $host =~ s/\/CRAM-MD5//i;

   if ( $opt_H ) {
	usage();
   }

   if ( $admin_user ) {
      $pwd = 'XXX';   # Don't need the user's password
   }

print "host $host pwd $pwd\n";
   unless ( $host and $user and $pwd ) {
	usage();
        exit;
   }


   return ($host,$user,$pwd);   

}

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
    print STDOUT ">> $cmd\n" if $showIMAP;
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
    print STDOUT "<< $response\n" if $showIMAP;
}

#  Make a connection to an IMAP host

sub connectToHost {

my $host = shift;
my $conn = shift;

   ($host,$port) = split(/:/, $host);
   $port = 143 unless $port;

   # We know whether to use SSL for ports 143 and 993.  For any
   # other ones we'll have to figure it out.
   $mode = sslmode( $host, $port );

   if ( $mode eq 'SSL' ) {
      unless( $ssl_installed == 1 ) {
         warn("You must have openSSL and IO::Socket::SSL installed to use an SSL connection");
         exit;
      }
      $$conn = IO::Socket::SSL->new(
         Proto           => "tcp",
         SSL_verify_mode => 0x00,
         PeerAddr        => $host,
         PeerPort        => $port,
         Domain          => AF_INET,
      );

      unless ( $$conn ) {
        $error = IO::Socket::SSL::errstr();
        warn("Error connecting to $host: $error");
        exit;
      }
   } else {
      #  Non-SSL connection
      $$conn = IO::Socket::INET->new(
         Proto           => "tcp",
         PeerAddr        => $host,
         PeerPort        => $port,
      );

      unless ( $$conn ) {
        warn "Error connecting to $host:$port: $@";
        exit;
      }
   } 

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


#  login
#
#  login in at the source host with the user's name and password
#
sub login {

my $user = shift;
my $pwd  = shift;
my $conn = shift;

   if ( uc( $method ) eq 'CRAM-MD5' ) {
      #  A CRAM-MD5 login is requested
      Log("login method $method");
      my $rc = login_cram_md5( $user, $pwd, $conn );
      return $rc;
   }

   if ( $admin_user ) {
      #  An AUTHENTICATE = PLAIN login has been requested
      ($authuser,$authpwd) = split(/:/, $admin_user );
      login_plain( $user, $authuser, $authpwd, $conn ) or exit;
      return 1;
   }

   if ( $pwd =~ /^oauth2:(.+)/i ) {
      $token = $1;
      Log("password is an OAUTH2 token");
      login_xoauth2( $user, $token, $conn );
      return 1;
   }

   sendCommand ($conn, "1 LOGIN $user $pwd");
   while (1) {
	readResponse ($conn);
	if ($response =~ /^1 OK/i) {
	   last;
	}
	elsif ($response !~ /^\*/) {
	   print STDOUT "Unexpected login response $response\n";
	   return 0;
	}
   }

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

   # sendCommand ($conn, "1 AUTHENTICATE \"PLAIN\" {$len}" );
   sendCommand ($conn, "1 AUTHENTICATE PLAIN" );

   my $loops;
   while (1) {
        readResponse ( $conn );
        last if $response =~ /\+/;
        if ($response =~ /^1 NO|^1 BAD|^\* BYE/i) {
           Log ("unexpected LOGIN response: $response");
           exit;
        }
        $last if $loops++ > 5;
   }

   sendCommand ($conn, "$login_str" );
   my $loops;
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
#  log out from the source host
#
sub logout {

my $conn = shift;

   # print STDOUT "Logging out\n" if $debug;
   sendCommand ($conn, "1 LOGOUT");
   while ( 1 ) {
	readResponse ($conn);
	if ( $response =~ /^1 OK/i ) {
	   last;
	}
	elsif ( $response !~ /^\*/ ) {
	   print STDOUT "unexpected LOGOUT response: $response\n";
	   last;
	}
   }
   close $conn;

   return;

}

  
sub usage {

   print STDOUT "\nUsage: imapPing.pl <args> \n\n";
   print STDOUT "   -h   <hostname>\n";
   print STDOUT "   -u   <user>\n"; 
   print STDOUT "   -p   <password>\n";
   print STDOUT "To use CRAM-MD5 for logins add /CRAM-MD5 like this:  -h hostname/CRAM-MD5\n";

   exit;

}


sub selectInbox {

my $mbx  = shift;
my $conn = shift;

   #  Select a mailbox

   sendCommand ($conn, "1 SELECT $mbx");
   while (1) {
	readResponse ($conn);
	if ($response =~ /^1 OK/i) {
	   last;
	}
	elsif ($response !~ /^\*/) {
	   print STDOUT "Unexpected SELECT INBOX response: $response\n";
	   return 0;
	}
   }

}

sub getMailboxList {

my $conn = shift;

   #  Get a list of the user's mailboxes
   
   sendCommand ($conn, "1 LIST \"\" *");
   @response = ();
   while ( 1 ) {
      readResponse ($conn);
      last if $response =~ /^1 OK/i;
	
      if ( $response !~ /^\*/ ) {
	 print STDOUT "unexpected response: $response\n";
         return 0;
      }
   }

   @mbxs = ();
   for $i (0 .. $#response) {
	# print STDERR "$response[$i]\n";
	$response[$i] =~ s/\s+/ /;
	($dmy,$mbx) = split(/"\/"/,$response[$i]);
	$mbx =~ s/^\s+//;  $mbx =~ s/\s+$//;
	$mbx =~ s/"//g;

	if ($mbx =~ /^\#/) {
	   #  Skip public mbxs
	   next;
	}

	if ($mbx ne '') {
	   push(@mbxs,$mbx);
	}
   }

   return 1;
}

sub getMsgList {

my $mailbox = shift;
my $conn    = shift;

   #  Select the mailbox in read-only mode

   sendCommand ($conn, "1 EXAMINE \"$mailbox\"");
   undef @response;
   $empty=0;
   while ( 1 ) {
    	readResponse ($conn);

        last if $response =~ /^1 OK/i;
    	
    	if ( $response !~ /^\*/ ) {
	   print STDOUT "Error: $response\n";
	   return 0;
    	}
   }

   sendCommand ($conn, "1 FETCH 1:* (UID FLAGS)");
   undef @response;
   while ( 1 ) {
	readResponse ($conn);
    	last if $response =~ /^1 OK/i;
        if ( $response !~ /^\*/ ) {
           print STDOUT "Unexpected response: $response\n";
	   return 0;
    	}
   }

   #  Get a list of the msgs in the mailbox
   #
   undef @msgs;
   for $i (0 .. $#response) {
	$_ = $response[$i];
        $_ =~ /\* ([^FETCH]*)/;
	$uid = $1;
	$uid =~ s/\s+$//;
   	if ($response[$i] =~ /\\Seen/) { $seen = 1; }
	if (($uid ne 'OK') && ($uid ne '')) {
		push (@msgs,"$uid $seen");
	}
   }
   return 1;
}

sub Log {

my $string = shift;

   print STDERR "$string\n";

}
