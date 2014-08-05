include admin::stages
include user::virtual
include user::developers

class { 'baseconfig':
  stage => 'pre'
}

class { 'ubuntu':
  require => Stage['pre']
}

class { [
  'pip',
    stage => 'post'
}

File {
  owner => 'vagrant',
  group => 'vagrant',
  mode  => '0644',
}

include baseconfig, ubuntu, pip
