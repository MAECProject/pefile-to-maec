# -*- mode: ruby -*-
# vi: set ft=ruby :

box      = 'trusty64'
url      = 'http://cloud-images.ubuntu.com/vagrant/trusty/20140730.1/trusty-server-cloudimg-amd64-vagrant-disk1.box'
ram      = '1024'
hostname = 'dev0'
cpu      = '1'

Vagrant.configure("2") do |config|
    config.vm.host_name = hostname
    config.ssh.shell = "bash -c 'BASH_ENV=/etc/profile exec bash'"
    config.vm.box = box
    config.vm.box_url = url

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

