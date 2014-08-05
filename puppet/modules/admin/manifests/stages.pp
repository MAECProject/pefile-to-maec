class admin::stages {
  stage { 'pre': before   => Stage['main'] }
  stage { 'post': require => Stage['main'] }
}
