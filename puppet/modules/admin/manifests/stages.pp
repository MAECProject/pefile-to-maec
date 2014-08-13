class admin::stages {
  stage { 'pre_install': before   => Stage['main'] }
  stage { 'base_install': require => Stage['pre_install'] }
  stage { 'python_prep': require => Stage['base_install'] }
  stage { 'custom_install': require => Stage['python_prep'] }
}
