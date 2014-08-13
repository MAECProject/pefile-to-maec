class maec { 
  package {'maec':
      provider => pip,
      require => Package['cybox'],
      ensure => present;
  }
}

