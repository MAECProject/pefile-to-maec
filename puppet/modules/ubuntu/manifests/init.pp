class ubuntu {
  package { [
    'python-dev',
    'python-setuptools',
    'python-pip',
    'libxml2-dev',
    'libxslt1-dev',
    'vim',
    'git',
    'zsh']:
      ensure => present;
  }

  exec { 'update_setuptools':
    command => '/usr/bin/sudo /usr/bin/pip install --upgrade setuptools',
    require => Package['python-dev', 'python-setuptools'];
  }

  exec { 'update_pip':
    command => '/usr/bin/sudo /usr/bin/pip install --upgrade pip',
    require => Exec['update_setuptools'];
  }
}
