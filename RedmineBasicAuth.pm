package Apache::Authn::RedmineBasicAuth;

=head1 Apache::Authn::RedmineBasicAuth

RedmineBasicAuth - a mod_perl module to do HTTP Basic authentication
against a Redmine database

=head1 Configuration

    PerlLoadModule Apache::RedmineBasicAuth
    <Location /some/dir/>
        AuthType Basic
        AuthName "RedmineBasicAuth"
        Require valid-user

        PerlAuthenHandler Apache::Authn::RedmineBasicAuth::authen_handler

        RedmineBasicAuthDSN "DBI:Pg:dbname=redmine_default;host=localhost"
        RedmineBasicAuthDbUser "redmine"
        RedmineBasicAuthDbPass "redmine"
    </Location>

=cut

use strict;
use warnings FATAL => 'all';

use threads;
use threads::shared;

use DBI;
use Digest::SHA1;

use Apache2::Access;
use Apache2::Module;
use Apache2::RequestRec;
use Apache2::Const qw(AUTH_REQUIRED OK OR_AUTHCFG TAKE1);

my @directives = (
    {
        name => 'RedmineBasicAuthDSN',
        req_override => OR_AUTHCFG,
        args_how => TAKE1,
        errmsg => '"DSN in format used by Perl DBI. eg: "DBI:Pg:dbname=databasename;host=my.db.server"',
    },
    {
        name => 'RedmineBasicAuthDbUser',
        req_override => OR_AUTHCFG,
        args_how => TAKE1,
    },
    {
        name => 'RedmineBasicAuthDbPass',
        req_override => OR_AUTHCFG,
        args_how => TAKE1,
    }
);

sub RedmineBasicAuthDSN {
    my ($self, $parms, $arg) = @_;

    $self->{RedmineBasicAuthDSN} = $arg;

    my $query = "SELECT hashed_password FROM users
                 WHERE login = ?";

    $self->{RedmineBasicAuthQuery} = trim($query);
}

sub RedmineBasicAuthDbUser { set_val('RedmineBasicAuthDbUser', @_); }
sub RedmineBasicAuthDbPass { set_val('RedmineBasicAuthDbPass', @_); }

# taken from Redmine.pm
sub trim {
    my $string = shift;
    $string =~ s/\s{2,}/ /g;
    return $string;
}

# taken from Redmine.pm
sub set_val {
    my ($key, $self, $parms, $arg) = @_;
    $self->{$key} = $arg;
}

Apache2::Module::add(__PACKAGE__, \@directives);

sub authen_handler {
    my $r = shift;

    my ($rc, $redmine_pass) = $r->get_basic_auth_pw();
    return $rc unless $rc == OK;

    return OK if is_valid($r->user, $redmine_pass, $r);

    $r->note_auth_failure();
    return AUTH_REQUIRED;
}

sub is_valid {
    my $redmine_user = shift;
    my $redmine_pass = shift;
    my $r = shift;

    my $redmine_pass_hash = Digest::SHA1::sha1_hex($redmine_pass);

    my $dbh = db_connect($r);

    my $cfg = Apache2::Module::get_config(__PACKAGE__,
                    $r->server, $r->per_dir_config);

    my $query = $cfg->{RedmineBasicAuthQuery};
    my $sth = $dbh->prepare($query);

    $sth->execute($redmine_user);

    my $ret;
    while (my ($hashed_password) = $sth->fetchrow_array) {
        if ($hashed_password eq $redmine_pass_hash) {
            $ret = 1;
            last;
        }
    }

    $sth->finish();
    undef $sth;

    $dbh->disconnect();
    undef $dbh;

    $ret;
}

my %cache :shared;
sub db_connect {
    my $r = shift;

    my $cfg = Apache2::Module::get_config(__PACKAGE__,
                    $r->server, $r->per_dir_config);

    return DBI->connect($cfg->{RedmineBasicAuthDSN},
                        $cfg->{RedmineBasicAuthDbUser},
                        $cfg->{RedmineBasicAuthDbPass},
                        \%cache);
}

1;
