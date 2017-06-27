#!/usr/bin/perl -w
# If your copy of perl is not in /usr/bin, please adjust the line above.
#
# Copyright (c) 2012-2014 VMware, Inc.  All rights reserved.
#
# Utility to manage the certifcates for 'grabbitmqproxy' plugin in
# 'VMware Tools'.

use strict;
use File::Compare;
use File::Copy;

my $gOpensslBinaryPath;
my $gGuestProxy_dir;
my $gGuestProxy_server_certs_dir;
my $gGuestProxy_server_trusted_dir;
my $gGuestProxy_ssl_conf;
my $gToolEtcDir = '/etc/vmware-tools';

# Tell if the user is the super user
sub is_root {
   return $> == 0;
}

# Emulate a simplified basename program
sub internal_basename {
   return substr($_[0], rindex($_[0], '/') + 1);
}

# Convert a string to its equivalent shell representation
sub shell_string {
   my $single_quoted = shift;

   return "'" . $single_quoted . "'";
}

# Print an error message and exit
sub error {
   my $msg = shift;

   print STDERR $msg . 'Execution aborted.' . "\n\n";

   exit 1;
}

# Display a usage error message for the 'certificate management' tool and exit.
sub config_usage {
   my $prog_name = internal_basename($0);
   my $usage = <<EOF;
Guest Proxy Certificate Management Tool.
Usage: $prog_name [OPTION] [ARGUMENTS]

Options
  -h, --help                     Prints the Usage information.

  -g, --generate_key_cert        Regenerate the server key/cert, the old
                                 key/cert will be replaced.

  -a, --add_trust_cert     <client_cert_pem_file>
                                 Adds the client cert to the trusted
                                 certificates directory.

  -r, --remove_trust_cert  <client_cert_pem_file>
                                 Remove the client cert from the trusted
                                 certificates directory.

  -d, --display_server_cert [<cert_pem_file>]
                                 Prints the server's certificate to the
                                 standard output. If the file path is specified,
                                 then the server's certificate is stored in
                                 the file.

EOF
   print STDERR $usage;
   exit 1;
}

sub getlibdir {
   my $installerDB = $gToolEtcDir . '/locations';

   my $libdir = '';

   if (not open(INSTALLDB, '<' . $installerDB)) {
      error('Unable to open the installer database ' . $installerDB
            . ' in read-mode.' . "\n\n");
   }

   while (<INSTALLDB>) {
      chomp;
      if (/^answer (\S+) (.+)$/) {
         if ($1 eq "LIBDIR") {
            $libdir = $2;
            last;
         }
      }
   }

   close(INSTALLDB);
   return $libdir;
}

# chmod for a file. Error if the chmod fails.
sub safe_chmod {
   my $mode = shift;
   my $file = shift;

   if (chmod($mode, $file) != 1) {
      error('Unable to change the access rights of the file ' . $file . '.'
            . "\n\n");
   }
}

#
# Certain operations --generate-key-cert, --add-trust-cert and
# --remove-trust-cert can be executed only by root user. So, check
# for 'root' user before performing such operations.
#
sub checkRootUser {
   if (not is_root()) {
      error('Plese re-run this program as the super user ' .
            'to execute this operation.' . "\n\n");
   }
}

# Validate the Tools Installation Environment
sub validateEnvironment {
   my $checkRoot = shift;
   if ($checkRoot) {
      checkRootUser();
   }
   my $libdir = getlibdir();
   if ($libdir eq '') {
      error("Couldn't find the libdir.\n\n");
   }

   if (not (-d $libdir)) {
      error("$libdir is not present.\n\n");
   }

   $gOpensslBinaryPath = $libdir . '/bin/' . 'openssl-0.9.8';
   $gGuestProxy_ssl_conf = $gToolEtcDir . "/guestproxy-ssl.conf";
   $gGuestProxy_dir = $gToolEtcDir . "/GuestProxyData";
   $gGuestProxy_server_certs_dir = $gGuestProxy_dir . "/server";
   $gGuestProxy_server_trusted_dir = $gGuestProxy_dir . "/trusted";

   if (not (-e $gOpensslBinaryPath)) {
      error("Couldn't find the library at $gOpensslBinaryPath for " .
            "generating the key and certificates.\n");
   }

   if (not (-d $gGuestProxy_dir)) {
      error("Couldn't find the GuestProxy Directory at " .
            "'$gGuestProxy_dir'.\n");
   }

   if (not (-d $gGuestProxy_server_certs_dir)) {
      error("Couldn't find the GuestProxy Certificate Directory at " .
            "'$gGuestProxy_server_certs_dir'.\n");
   }

   if (not (-d $gGuestProxy_server_trusted_dir)) {
      error("Couldn't find the GuestProxy Certificate Store at " .
            "'$gGuestProxy_server_trusted_dir'.\n");
   }

   if (not (-f $gGuestProxy_ssl_conf)) {
      error("Couldn't find the GuestProxy Config file at " .
            "'$gGuestProxy_ssl_conf'.\n");
   }
}

# Generate the key and certficate.
sub generate_key_cert {

   validateEnvironment(1);

   my $guestproxy_server_key_pem  = $gGuestProxy_server_certs_dir . '/key.pem';
   my $guestproxy_server_cert_pem = $gGuestProxy_server_certs_dir . '/cert.pem';

   print "Generating the Key file\n\n";
   if (system(shell_string($gOpensslBinaryPath) .
              ' genrsa' .
              ' -out '  . shell_string($guestproxy_server_key_pem) .
              ' 2048')) {
     error("Failed to Create key.pem file with error: " . $? . "\n\n");
   } else {
     # Setuid root
     chmod(0600, $guestproxy_server_key_pem);
   }

   print "Generating the Certificate file\n\n";

   if (system(shell_string($gOpensslBinaryPath) .
              ' req'   .
              ' -new'  .
              ' -x509' .
              ' -config ' . shell_string($gGuestProxy_ssl_conf) .
              ' -key ' . shell_string($guestproxy_server_key_pem) .
              ' -out ' . shell_string($guestproxy_server_cert_pem))) {
     print "Failed to create cert.pem file with error: " . $? . "\n\n";
   } else {
     # Setuid root
     safe_chmod(0644, $guestproxy_server_cert_pem);
   }

   print "Successfully generated the key and Certificate files.\n";
}

# Compute the hash for a specified certificate
sub computeHash {
   my $certFilePath = shift;
   my $command = shell_string($gOpensslBinaryPath) .
                 ' x509 -hash -noout -in ' .
                 shell_string($certFilePath);
   my $hashComputed = `$command`;
   if ($? !=0) {
      error("Unable to compute the hash. Error: $?.\n\n");
   }
   chomp($hashComputed);
   return $hashComputed;
}

# Sort the list of files.
sub fileListSortFunction {
   $a =~ m/[^.]+\.(\d+)/;
   my $firstNumber = int($1);

   $b =~ m/[^.]+\.(\d+)/;
   my $secondNumber = int($1);

   return $firstNumber - $secondNumber;
}

# Searches the specified directory and returns the list of all files with
# name matching the specified pattern.
sub getFileList {
   my $directoryPath = shift ||
                       error("The directory to search is not specified.\n\n");
   my $searchFilter = shift || '';
   my @fileList;

   opendir(DIR, $directoryPath) or
      error("Failed to read directory '$directoryPath'. Error: $?\n\n");

   while (my $file = readdir(DIR)) {
      my $fileFullPath = $directoryPath . '/' . $file;
      if (not (-f $fileFullPath)) {
         # Ignore if this is not a file
         next;
      }

      # Check if the filename matches the specified pattern.
      if ($file =~ m/$searchFilter/) {
         push(@fileList, $file);
      }
   }

   closedir DIR;

   return @fileList;
}

# Add a certificate file to the trusted certificate repository.
sub add_trust_cert {
   my $certFilePath = shift ||
                      error("Must specify the name of the certificate " .
                            "file that should be added." . "\n\n");

   validateEnvironment(1);

   if (not (-e $certFilePath)) {
      error("No Certificate file found at '$certFilePath'.\n\n");
   }

   my $hashComputed = computeHash($certFilePath);
   my $fileSearchPattern = '^' . $hashComputed . '.(\d+)$';
   my @fileList = getFileList($gGuestProxy_server_trusted_dir, $fileSearchPattern);

   @fileList = sort fileListSortFunction @fileList;

   foreach (@fileList) {
      if (!compare($certFilePath,
                   $gGuestProxy_server_trusted_dir . '/' . $_)) {
         # The certificate already exists in the 'truested' directory.
         # Consider this as no-op.
         print "The specified Certificate file already exists.\n\n";
         return;
      }
   }

   my $newCertFileName = $hashComputed . '.0';
   my $lastFileElement = shift(@fileList);
   if ($lastFileElement) {
      $lastFileElement =~ m/$fileSearchPattern/;
      $newCertFileName = $hashComputed . '.' . (int($1) + 1);
   }
   copy($certFilePath,
        $gGuestProxy_server_trusted_dir . '/' . $newCertFileName) or
        error("Failed to add the certificate file. Error: $?\n\n");

   print("Successfully added the $certFilePath to the " .
         "Trusted Certificate store.\n\n");
}

# Remove a certificate file from the trusted certficate repository.
sub remove_trust_cert {
   my $certFilePath = shift ||
                      error("Must specify the name of the certificate " .
                            "file that should be removed." . "\n\n");

   validateEnvironment(1);

   if (not (-e $certFilePath)) {
      error("No Certificate file found at '$certFilePath'.\n\n");
   }

   my $hashComputed = computeHash($certFilePath);
   my $fileSearchPattern = '^' . $hashComputed . '.(\d+)$';
   my @fileList = getFileList($gGuestProxy_server_trusted_dir,
                              $fileSearchPattern);

   @fileList = sort fileListSortFunction @fileList;

   my $certFileToRemove;

   foreach (@fileList) {
      my $tmpFileFullPath = $gGuestProxy_server_trusted_dir . '/' . $_;
      if (!compare($certFilePath, $tmpFileFullPath)) {
         $certFileToRemove = $tmpFileFullPath;
         last;
      }
   }

   if ($certFileToRemove) {
      my $lastFileElement = shift(@fileList);
      my $lastFileElementFullPath = $gGuestProxy_server_trusted_dir . '/' .
                                    $lastFileElement;
      my $success;
      if ($certFileToRemove eq $lastFileElementFullPath) {
         $success = unlink($certFileToRemove);
      } else {
         $success = move($lastFileElementFullPath, $certFileToRemove);
      }
      if ($success) {
         print "Successfully removed the Certificate.\n";
      } else {
         print "Failed to remove the Certificate. Error: $!.\n";
      }
   } else {
      print "Couldn't find any certificate in the trusted directory.\n";
   }
}

# Display the server certificate
sub display_server_cert {
   my $outputFilePath = shift;
   validateEnvironment(0);

   my $guestproxy_server_cert_pem = $gGuestProxy_server_certs_dir . '/cert.pem';
   if (not (-f $guestproxy_server_cert_pem)) {
      error("Couldn't find the Server Certificate file.\n\n");
   }

   open IN, "<$guestproxy_server_cert_pem" or
      error("Couldn't open the Server Certificate file. Error: $!.\n\n");

   if ($outputFilePath) {
      if (not open OUT, ">$outputFilePath") {
         close IN;
         error("Couldn't write the certificate to the file. Error: $!.\n\n");
      }
      print "Copying the server certificate to $outputFilePath.\n";
      print OUT <IN>;
      close OUT;
      print "Successfully copied the server certificate..\n";
   } else {
      print STDOUT <IN>;
   }

   close IN;
}

# Program entry point
sub main {
   # Force the path to reduce the risk of using "modified" external helpers.
   # If the user has a special system setup, he will be prompted for the
   # proper location anyway.
   $ENV{'PATH'} = '/bin:/usr/bin:/sbin:/usr/sbin';

   # List of questions answered with command-line arguments
   # Command line analysis
   my $arg = shift(@ARGV);

   if ($arg) {
      if (lc($arg) =~ /^(-)?(-)?h(elp)?$/) {
         config_usage();
       } elsif (lc($arg) =~ /^(-)?(-)?g(enerate_key_cert)?$/) {
         generate_key_cert();
       } elsif (lc($arg) =~ /^(-)?(-)?a(dd_trust_cert)?$/) {
         add_trust_cert(shift(@ARGV));
       } elsif (lc($arg) =~ /^(-)?(-)?r(emove_trust_cert)?$/) {
         remove_trust_cert(shift(@ARGV));
       } elsif (lc($arg) =~ /^(-)?(-)?d(isplay_server_cert)?$/) {
         display_server_cert(shift(@ARGV));
       } else {
         print STDERR "Unknown Option: $arg\n";
         config_usage();
       }
   } else {
      print STDERR "Missing Option.\n";
      config_usage();
   }
}

main();
