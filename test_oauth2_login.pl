#!/usr/bin/perl

# $Header: /mhub4/sources/imap-tools/test_oauth2_login.pl,v 1.1 2015/07/11 13:33:45 rick Exp $

#######################################################################
#  Program name    test_oauth2_login.pl                               #
#  Written by      Rick Sanders, IMAP Tools                           #
#  Date            11-July-2015                                       #
#                                                                     #
#  This short script can be used to test OAUTH2 login into Gmail      #
#  Usage:  ./test_oauth2_login.pl <gmail username> <OAUTH2 token>     #
#######################################################################

use Socket;
use Getopt::Std;
use Encode qw/encode decode/;
use MIME::Base64 qw(decode_base64 encode_base64);

   init();
   get_info( \$user, \$token );
   connectToHost( 'imap.gmail.com:993', \$conn ) or exit;
   login_xoauth2( $user, $token, $conn ) or exit;

   print "\nLogin was successful\n\n";

   logout( $conn );

   exit;


sub init {

   #  Determine whether we have SSL support via openSSL and IO::Socket::SSL

   $ssl_installed = 1;
   eval 'use IO::Socket::SSL';
   if ( $@ ) {
      $ssl_installed = 0;
   }
}

sub get_info {

my $user  = shift;
my $token = shift;

   if ( $ARGV[0] and $ARGV[1] ) {
      $$user = $ARGV[0];
      $$token = $ARGV[1];
   } else {
      print "User:  ";
      $$user = <>;
      chomp $$user;
      print "Token: ";
      $$token = <>;
      chomp $$token;
   }

}

#
#  sendCommand
#
#  This subroutine formats and sends an IMAP protocol command to an
#  IMAP server on a specified connection.
#

sub sendCommand {

my $fd = shift;
my $cmd = shift;

    #  If we've had to reconnect use the new connection
    if ( $CONNECTIONS{"$fd"} ) {
       $fd = $CONNECTIONS{"$fd"};
       Log("Using the new connection $fd");
    }

    print $fd "$cmd\r\n";

    Log (">> $cmd") if $showIMAP;
}

#
#  readResponse
#
#  This subroutine reads and formats an IMAP protocol response from an
#  IMAP server on a specified connection.
#

sub readResponse {
    
my $fd = shift;

    #  If we've had to reconnect use the new connection
    if ( $CONNECTIONS{"$fd"} ) {
       $fd = $CONNECTIONS{"$fd"};
       Log("Using the new connection $fd");
    }

    $response = <$fd>;
    chop $response;
    $response =~ s/\r//g;
    push (@response,$response);
    Log ("<< $response") if $showIMAP;

    if ( $response =~ /\* BAD internal server error/i ) {
       Log("Fatal IMAP server error:  $response");
       exit;
    }

    if ( $exchange and $response =~ /^1 NO|^1 BAD/ ) {
       $errors++;
       exchange_workaround() if $errors == 9;
    }

    if ( $response =~ /connection closed/i ) {
       ($src,$dst) = reconnect();
    }
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
   # Log("Connected to $host on port $port");

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

#  login_xoauth2
#
#  login in at the source host with the user's name and an XOAUTH2 token.  
#
sub login_xoauth2 {

my $user      = shift;
my $token     = shift;
my $conn      = shift;

   #  Do an AUTHENTICATE = XOAUTH2 login

   $showIMAP = 1;
   $login_str = encode_base64("user=". $user ."\x01auth=Bearer ". $token ."\x01\x01", '');
   sendCommand ($conn, "1 AUTHENTICATE XOAUTH2 $login_str" );

   my $loops;
   while (1) {
        readResponse ( $conn );
        if ( $response =~ /^\+ (.+)/ ) {
           $error = decode_base64( $1 );
           Log("XOAUTH authentication as $user failed: $error");
           exit;
        }
        last if $response =~ /^1 OK/;
        if ($response =~ /^1 NO|^1 BAD|^\* BYE|failed/i) {
           Log ("unexpected LOGIN response: $response");
           exit;
        }
        $last if $loops++ > 5;
   }

   Log("login complete") if $debug;

   return 1;

}

#  logout
#
#  log out from the host
#
sub logout {

my $conn = shift;

   undef @response;
   sendCommand ($conn, "1 LOGOUT");
   while ( 1 ) {
	readResponse ($conn);
	if ( $response =~ /^1 OK/i ) {
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

sub Log {

my $string = shift;

   print "$string\n";

}
