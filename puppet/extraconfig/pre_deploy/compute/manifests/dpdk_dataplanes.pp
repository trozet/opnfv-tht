# Copyright 2016 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# Disable selinux
exec {'disable selinux':
  command => '/usr/sbin/setenforce 0',
  unless  => '/usr/sbin/getenforce | grep Permissive',
}

file_line {'selinux':
  path  => '/etc/selinux/config',
  line  => 'SELINUX=permissive',
  match => '^SELINUX=.*$',
}
$tenant_nic = hiera('tenant_nic')

$dpdk_tenant_port = hiera("${tenant_nic}", false)

if ! $dpdk_tenant_port { fail("Cannot find physical port name for logical port ${dpdk_tenant_port}")}

$dpdk_tenant_pci_addr = inline_template("<%= `ethtool -i ${dpdk_tenant_port} | grep bus-info | awk {'print \$2'}`.chomp %>")

if ! $dpdk_tenant_pci_addr { fail("Cannot find PCI address of ${dpdk_tenant_port}")}

if hiera('fdio_enabled', false) {
$dpdk_tenant_port_ip_var = "ipaddress_$dpdk_tenant_port"
$dpdk_tenant_port_ip = inline_template("<%= scope.lookupvar(@dpdk_tenant_port_ip_var) %>")
if ! $dpdk_tenant_port_ip { fail("Cannot find IP address of ${dpdk_tenant_port}")}

$dpdk_tenant_port_netmask_var = "netmask_$dpdk_tenant_port"
$dpdk_tenant_port_cidr = inline_template("<%= require 'ipaddr'; IPAddr.new(scope.lookupvar(@dpdk_tenant_port_netmask_var)).to_i.to_s(2).count('1') %>")
if ! $dpdk_tenant_port_cidr { fail("Cannot find cidr of ${dpdk_tenant_port}")}

#  $public_nic = hiera('public_nic')

#  $dpdk_public_port = hiera("${public_nic}", false)

#  if ! $dpdk_public_port { fail("Cannot find physical port name for logical port ${public_nic}")}

#  $dpdk_public_pci_addr = inline_template("<%= `ethtool -i ${dpdk_public_port} | grep bus-info | awk {'print \$2'}` %>")

#  if ! $dpdk_public_pci_addr { fail("Cannot find PCI address of ${dpdk_public_port}")}

  service { "openvswitch":
    ensure     => "stopped",
    enable     => false,
    hasrestart => true,
    restart    => '/usr/bin/systemctl restart openvswitch',
  }
  file { "vpp dpdk_bind_lock file":
    path   => '/root/dpdk_bind_lock',
    ensure => present
  }->
  class { '::fdio':
    fdio_dpdk_pci_devs => [ $dpdk_tenant_pci_addr ],
    fdio_nic_names     => [ $dpdk_tenant_port ],
    fdio_ips           => [ "${dpdk_tenant_port_ip}/${dpdk_tenant_port_cidr}" ],
  }

  if 'opendaylight' in hiera('neutron::plugins::ml2::mechanism_drivers') {
    class { '::fdio::honeycomb':
      rest_port => '8182',
      require   => Class['::fdio'],
    }

  }

} else {
  service { "openvswitch":
    ensure     => "running",
    enable     => true,
    hasrestart => true,
    restart    => '/usr/bin/systemctl restart openvswitch',
  }

  file_line { 'ovs_dpdk_conf':
    path  => '/etc/sysconfig/openvswitch',
    line  => 'DPDK_OPTIONS="-l 1,2 -n 1 --socket-mem 1024,0"',
    match => '^DPDK_OPTIONS=.*$',
  }
  ~>
  Service['openvswitch']


  $dpdk_bind_type = hiera("dpdk_pmd_type")
  exec { 'remove regular interface':
    command => "ovs-vsctl del-port br-phy ${dpdk_tenant_port}",
    onlyif  => "ovs-vsctl list-ports br-phy | grep ${dpdk_tenant_port}",
    path    => '/usr/sbin:/usr/bin:/sbin:/bin',
  }
  ->
  exec { 'bind_dpdk_port':
    command  => "dpdk_nic_bind --force --bind=${dpdk_bind_type} ${dpdk_tenant_pci_addr}",
    path     => "/usr/sbin/",
    creates  => '/root/dpdk_bind_lock'
  }
  ->
  file {'/root/dpdk_bind_lock':
    ensure => present
  }

  exec { 'set ovs bridge datapath':
    command => 'ovs-vsctl set bridge br-phy datapath_type=netdev',
    unless  => 'ovs-vsctl list bridge br-phy | grep datapath_type | grep netdev',
    path    => '/usr/sbin:/usr/bin:/sbin:/bin',
    require => Exec['bind_dpdk_port'],
    notify  => Service['openvswitch'],
  }
  ->
  exec { 'add dpdk port to ovs':
    command => 'ovs-vsctl add-port br-phy dpdk0 -- set Interface dpdk0 type=dpdk',
    unless  => 'ovs-vsctl list-ports br-phy | grep dpdk0',
    path    => '/usr/sbin:/usr/bin:/sbin:/bin',
  }
  ->
  exec { 'br-phy patch port':
    command => 'ovs-vsctl add-port br-phy patch-br-phy -- set Interface patch-br-phy type=patch options:peer=patch-br-tun',
    unless  => 'ovs-vsctl list-ports br-phy | grep patch-br-phy',
    path    => '/usr/sbin:/usr/bin:/sbin:/bin',
  }
  ->
  exec { 'br-tun patch port':
    command => 'ovs-vsctl add-port br-tun patch-br-tun -- set Interface patch-br-tun type=patch options:peer=patch-br-phy',
    unless  => 'ovs-vsctl list-ports br-tun | grep patch-br-tun',
    path    => '/usr/sbin:/usr/bin:/sbin:/bin',
  }

}
