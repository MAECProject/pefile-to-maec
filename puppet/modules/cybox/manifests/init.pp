class cybox {
  package {'cybox':
    provider => pip,
    require => Package['lxml'],
    ensure => present;
  }
}
