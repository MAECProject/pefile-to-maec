class ubuntu {
  package { [
    'build-essential',
    'python-dev',
    'python-setuptools',
    'python-pip',
    'python-dateutil',
    'g++',
    'zlib1g-dev',
    'libxml2-dev',
    'libxslt1-dev',
    'vim',
    'git',
    'zsh']:
      install_options => ['--force-yes'],
      require => Class['baseconfig'],
      ensure => present;
  }
}
