include admin::stages
include user::virtual
include user::developers

class { 'baseconfig':
  stage => 'pre_install'
}

class { 'ubuntu':
  stage => 'base_install'
}

class { 'pip':
  stage => 'python_prep'
}

class { [
  'cybox',
  'maec']:
    stage => 'custom_install'
}

File {
  owner => 'vagrant',
  group => 'vagrant',
  mode  => '0644',
}

include baseconfig, ubuntu, pip, cybox, maec
