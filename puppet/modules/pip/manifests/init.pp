class pip {
  package { [
  'ipython',
  'numpy',
  'pandas',
  'lxml']:
    provider => pip,
    ensure   => present;
  }
}

