class user::virtual {
  define ssh_user($key) {
    user { $name:
      ensure     => present,
      managehome => true,
    }

    file { "/home/${name}/.ssh":
      ensure => directory,
      mode   => '0700',
      owner  => $name,
    }

    ssh_authorized_key { "${name}_key":
      key     => $key,
      type    => 'ssh-rsa',
      user    => $name,
      require => File["/home/${name}/.ssh"],
    }
  }

  @ssh_user { 'vagrant':
    key => 'AAAAB3NzaC1yc2EAAAADAQABAAABAQDTvWHgANB+L1oy6us6JjqllZkinyq1qR9v8lflDSglSJS7mXXKlaB9rsiZ4awwto/JR3LqC8i0GiazbaauD1hbY6t0hdAsrcbXxuFUzMdTsareZn7lWc4nmX6yavQ9ulmGk/NJBslmCZuvhmXNmXS+Ypwp8MwMqMBxXK2Pe6giNj1tejPZ1Muhxec8Fvf0Wi5a5dd09j2JhqbydjoDwSBrXlwVpG6DchLW8iNEHTOMEX0loq/QkRO2JLYd+bWHocydjzy0lEbyZ78bSR4OHPk5CACLNaEjElwe1baDxrjBsQoCZcS5o15opfslzTIrp1lhqrolNbw8jg8RApTmF3t9',
  }
}

