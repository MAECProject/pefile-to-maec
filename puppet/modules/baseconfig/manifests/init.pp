class baseconfig {
  exec { 'apt-get update':
    command => '/usr/bin/sudo /usr/bin/apt-get update';
  }

  package { 'build-essential':
    require => Exec['apt-get update'],
    ensure  => installed;
  }
}

