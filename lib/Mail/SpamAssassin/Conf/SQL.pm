# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

Mail::SpamAssassin::Conf::SQL - load SpamAssassin scores from SQL database

=head1 SYNOPSIS

  (see Mail::SpamAssassin)
  

=head1 DESCRIPTION

Mail::SpamAssassin is a module to identify spam using text analysis and
several internet-based realtime blacklists.

This class is used internally by SpamAssassin to load scores from an SQL
database.  Please refer to the C<Mail::SpamAssassin> documentation for public
interfaces.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::Conf::SQL;

# Make the main dbg() accessible in our package w/o an extra function
*dbg=\&Mail::SpamAssassin::dbg;

use strict;
use warnings;
use bytes;
use Carp;

use vars qw{
  @ISA
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main) = @_;

  my $self = {
    'main'              => $main
  };

  bless ($self, $class);
  $self;
}

###########################################################################

sub load_modules {		# static
  eval {
    require DBI;
  };

  # do any other preloading that will speed up operation
}

###########################################################################

=item $f->load ($username)

Read configuration paramaters from SQL database and parse scores from it.

=cut

sub load {
   my ($self, $username) = @_;

   my $dsn = $self->{main}->{conf}->{user_scores_dsn};
   if(!defined($dsn) || $dsn eq '') {
     dbg("config: no DSN defined; skipping sql");
     return 1;
   }

   eval {
     # make sure we can see croak messages from DBI
     local $SIG{'__DIE__'} = sub { die "$_[0]"; };
     require DBI;
     load_with_dbi($self, $username, $dsn);
   };

   if ($@) {
     warn "config: failed to load user ($username) scores from SQL database: $@\n";
     return 0;
   }
   return 1;
}

sub load_with_dbi {
   my ($self, $username, $dsn) = @_;

   my $main = $self->{main};
   my $dbuser = $main->{conf}->{user_scores_sql_username};
   my $dbpass = $main->{conf}->{user_scores_sql_password};
   my $custom_query = $main->{conf}->{user_scores_sql_custom_query};

   my $f_preference = 'preference';
   my $f_value = 'value';
   my $f_username = 'username';
   my $f_table = 'userpref';

   my $dbh = DBI->connect($dsn, $dbuser, $dbpass, {'PrintError' => 0});

   if($dbh) {
     my $sql;
     if (defined($custom_query)) {
       $sql = $custom_query;
       my $quoted_username = $dbh->quote($username);
       my ($mailbox, $domain) = split('@',$username);
       my $quoted_mailbox = $dbh->quote($mailbox);
       my $quoted_domain = $dbh->quote($domain);

       $sql =~ s/_USERNAME_/$quoted_username/g;
       $sql =~ s/_TABLE_/$f_table/g;
       $sql =~ s/_MAILBOX_/$quoted_mailbox/g;
       $sql =~ s/_DOMAIN_/$quoted_domain/g;
     }
     else {
       $sql = "select $f_preference, $f_value  from $f_table where ". 
        "$f_username = ".$dbh->quote($username).
        " or $f_username = '\@GLOBAL' order by $f_username asc";
     }
     dbg("config: Conf::SQL: executing SQL: $sql");
      my $sth = $dbh->prepare($sql);
      if($sth) {
         my $rv  = $sth->execute();
         if($rv) {
            dbg("config: retrieving prefs for $username from SQL server");
            my @row;
            my $text = '';
            while(@row = $sth->fetchrow_array()) {
               $text .= "$row[0]\t$row[1]\n";
            }
            if($text ne '') {
	      $main->{conf}->{main} = $main;
	      $main->{conf}->parse_scores_only(join('',$text));
	      delete $main->{conf}->{main};
            }
            $sth->finish();
         } else { die "config: SQL error: $sql\n".$sth->errstr."\n"; }
      } else { die "config: SQL error: " . $dbh->errstr . "\n"; }
   $dbh->disconnect();
   } else { die "config: SQL error: " . DBI->errstr . "\n"; }
}

###########################################################################

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

###########################################################################

1;
