class pip {
  package { [
  'virtualenv',
  'virtualenvwrapper',
  'ipython',
  'pandas',
  'cybox',
  'maec']:
    ensure   => installed,
    provider => pip;
  }
}

