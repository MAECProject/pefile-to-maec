# -*- mode: ruby -*-
# vi: set ft=ruby :

box      = 'hashicorp/precise64'
ram      = '1024'
hostname = 'maec1'
cpu      = '1'

Vagrant.configure("2") do |config|
    config.vm.host_name = hostname
    config.ssh.shell = "bash -c 'BASH_ENV=/etc/profile exec bash'"
    config.vm.box = box

    config.vm.provider "virtualbox" do |vb|
        vb.gui = false
        vb.customize [
            'modifyvm', :id,
            '--memory', ram,
            '--cpus', cpu,
        ]
    end

    config.vm.provision :puppet do |puppet|
        puppet.manifests_path = 'puppet/manifests'
        puppet.manifest_file = 'site.pp'
        puppet.module_path = 'puppet/modules'
    end
end

