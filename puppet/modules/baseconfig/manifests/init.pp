class baseconfig {
  exec { 'apt-get update':
    command => '/usr/bin/sudo /usr/bin/apt-get update';
  }
}

