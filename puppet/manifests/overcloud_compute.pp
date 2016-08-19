# Copyright 2014 Red Hat, Inc.
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

include ::tripleo::packages
include ::tripleo::firewall

create_resources(kmod::load, hiera('kernel_modules'), {})
create_resources(sysctl::value, hiera('sysctl_settings'), {})
Exec <| tag == 'kmod::load' |>  -> Sysctl <| |>

if count(hiera('ntp::servers')) > 0 {
  include ::ntp
}

include ::timezone

file { ['/etc/libvirt/qemu/networks/autostart/default.xml',
        '/etc/libvirt/qemu/networks/default.xml']:
  ensure => absent,
  before => Service['libvirt'],
}
# in case libvirt has been already running before the Puppet run, make
# sure the default network is destroyed
exec { 'libvirt-default-net-destroy':
  command => '/usr/bin/virsh net-destroy default',
  onlyif  => '/usr/bin/virsh net-info default | /bin/grep -i "^active:\s*yes"',
  before  => Service['libvirt'],
}

# When utilising images for deployment, we need to reset the iSCSI initiator name to make it unique
exec { 'reset-iscsi-initiator-name':
  command => '/bin/echo InitiatorName=$(/usr/sbin/iscsi-iname) > /etc/iscsi/initiatorname.iscsi',
  onlyif  => '/usr/bin/test ! -f /etc/iscsi/.initiator_reset',
}->

file { '/etc/iscsi/.initiator_reset':
  ensure => present,
}

include ::nova
include ::nova::config
include ::nova::compute

$rbd_ephemeral_storage = hiera('nova::compute::rbd::ephemeral_storage', false)
$rbd_persistent_storage = hiera('rbd_persistent_storage', false)
if $rbd_ephemeral_storage or $rbd_persistent_storage {
  if str2bool(hiera('ceph_ipv6', false)) {
    $mon_host = hiera('ceph_mon_host_v6')
  } else {
    $mon_host = hiera('ceph_mon_host')
  }
  class { '::ceph::profile::params':
    mon_host            => $mon_host,
  }
  include ::ceph::conf
  include ::ceph::profile::client

  $client_keys = hiera('ceph::profile::params::client_keys')
  $client_user = join(['client.', hiera('ceph_client_user_name')])
  class { '::nova::compute::rbd':
    libvirt_rbd_secret_key => $client_keys[$client_user]['secret'],
  }
}

# Enable Ceph Storage (OSD) on the Compute Nodes
if str2bool(hiera('enable_ceph_storage', false)) {
  if str2bool(hiera('ceph_osd_selinux_permissive', true)) {
    exec { 'set selinux to permissive on boot':
      command => "sed -ie 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config",
      onlyif  => "test -f /etc/selinux/config && ! grep '^SELINUX=permissive' /etc/selinux/config",
      path    => ['/usr/bin', '/usr/sbin'],
    }

    exec { 'set selinux to permissive':
      command => 'setenforce 0',
      onlyif  => "which setenforce && getenforce | grep -i 'enforcing'",
      path    => ['/usr/bin', '/usr/sbin'],
    } -> Class['ceph::profile::osd']
  }

  include ::ceph::profile::client
  include ::ceph::profile::osd
}

if hiera('cinder_enable_nfs_backend', false) {
  if str2bool($::selinux) {
    selboolean { 'virt_use_nfs':
      value      => on,
      persistent => true,
    } -> Package['nfs-utils']
  }

  package {'nfs-utils': } -> Service['nova-compute']
}

if str2bool(hiera('nova::use_ipv6', false)) {
  $vncserver_listen = '::0'
} else {
  $vncserver_listen = '0.0.0.0'
}
class { '::nova::compute::libvirt' :
  vncserver_listen => $vncserver_listen,
}

nova_config {
  'DEFAULT/my_ip':                     value => $ipaddress;
  'DEFAULT/linuxnet_interface_driver': value => 'nova.network.linux_net.LinuxOVSInterfaceDriver';
  'DEFAULT/host':                      value => $fqdn;
  # TUNNELLED mode provides a security enhancement when using shared storage but is not
  # supported when not using shared storage.
  # See https://bugzilla.redhat.com/show_bug.cgi?id=1301986#c12
  # In future versions of QEMU (2.6, mostly), Dan's native encryption
  # work will obsolete the need to use TUNNELLED transport mode.
  'libvirt/live_migration_tunnelled':  value => $rbd_ephemeral_storage;
}

if hiera('neutron::core_plugin') == 'midonet.neutron.plugin_v1.MidonetPluginV2' {
  file {'/etc/libvirt/qemu.conf':
    ensure  => present,
    content => hiera('midonet_libvirt_qemu_data')
  }
}
include ::nova::network::neutron
include ::neutron
include ::neutron::config

# If the value of core plugin is set to 'nuage',
# include nuage agent,
# If the value of core plugin is set to 'midonet',
# include midonet agent,
# else use the default value of 'ml2'
if hiera('neutron::core_plugin') == 'neutron.plugins.nuage.plugin.NuagePlugin' {
  include ::nuage::vrs
  include ::nova::compute::neutron

  class { '::nuage::metadataagent':
    nova_os_tenant_name => hiera('nova::api::admin_tenant_name'),
    nova_os_password    => hiera('nova_password'),
    nova_metadata_ip    => hiera('nova_metadata_node_ips'),
    nova_auth_ip        => hiera('keystone_public_api_virtual_ip'),
  }
}
elsif hiera('neutron::core_plugin') == 'midonet.neutron.plugin_v1.MidonetPluginV2' {

  # TODO(devvesa) provide non-controller ips for these services
  $zookeeper_node_ips = hiera('neutron_api_node_ips')
  $cassandra_node_ips = hiera('neutron_api_node_ips')

  class {'::tripleo::network::midonet::agent':
    zookeeper_servers => $zookeeper_node_ips,
    cassandra_seeds   => $cassandra_node_ips
  }
}
elsif hiera('neutron::core_plugin') == 'neutron_plugin_contrail.plugins.opencontrail.contrail_plugin.NeutronPluginContrailCoreV2' {

  include ::contrail::vrouter
  # NOTE: it's not possible to use this class without a functional
  # contrail controller up and running
  #class {'::contrail::vrouter::provision_vrouter':
  #  require => Class['contrail::vrouter'],
  #}
}
elsif hiera('neutron::core_plugin') == 'networking_plumgrid.neutron.plugins.plugin.NeutronPluginPLUMgridV2' {
  # forward all ipv4 traffic
  # this is required for the vms to pass through the gateways public interface
  sysctl::value { 'net.ipv4.ip_forward': value => '1' }

  # ifc_ctl_pp needs to be invoked by root as part of the vif.py when a VM is powered on
  file { '/etc/sudoers.d/ifc_ctl_sudoers':
    ensure  => file,
    owner   => root,
    group   => root,
    mode    => '0440',
    content => "nova ALL=(root) NOPASSWD: /opt/pg/bin/ifc_ctl_pp *\n",
  }
}
else {

  include ::neutron::plugins::ml2

  if 'opendaylight' in hiera('neutron::plugins::ml2::mechanism_drivers') {

    if str2bool(hiera('opendaylight_install', 'false')) {
      $controller_ips = split(hiera('controller_node_ips'), ',')
      if hiera('opendaylight_enable_ha', false) {
        $odl_ovsdb_iface = "tcp:${controller_ips[0]}:6640 tcp:${controller_ips[1]}:6640 tcp:${controller_ips[2]}:6640"
        # Workaround to work with current puppet-neutron
        # This isn't the best solution, since the odl check URL ends up being only the first node in HA case
        $opendaylight_controller_ip = $controller_ips[0]
        # Bug where netvirt:1 doesn't come up right with HA
        # Check ovsdb:1 instead
        $net_virt_url = 'restconf/operational/network-topology:network-topology/topology/ovsdb:1'
      } else {
        $opendaylight_controller_ip = $controller_ips[0]
        $odl_ovsdb_iface = "tcp:${opendaylight_controller_ip}:6640"
        $net_virt_url = 'restconf/operational/network-topology:network-topology/topology/netvirt:1'
      }
    } else {
      $opendaylight_controller_ip = hiera('opendaylight_controller_ip')
      $odl_ovsdb_iface = "tcp:${opendaylight_controller_ip}:6640"
      $net_virt_url = 'restconf/operational/network-topology:network-topology/topology/netvirt:1'
    }

    $opendaylight_port = hiera('opendaylight_port')
    $private_ip = hiera('neutron::agents::ml2::ovs::local_ip')
    $opendaylight_url = "http://${opendaylight_controller_ip}:${opendaylight_port}/${net_virt_url}"

    # co-existence hacks for SFC
    if hiera('opendaylight_features', 'odl-ovsdb-openstack') =~ /odl-ovsdb-sfc-rest/ {
      $odl_username = hiera('opendaylight_username')
      $odl_password = hiera('opendaylight_password')
      $sfc_coexist_url = "http://${opendaylight_controller_ip}:${opendaylight_port}/restconf/config/sfc-of-renderer:sfc-of-renderer-config"
      # Coexist for SFC
      exec { 'Check SFC table offset has been set':
        command   => "curl --fail --silent -u ${odl_username}:${odl_password} ${sfc_coexist_url} | grep :11 > /dev/null",
        tries     => 15,
        try_sleep => 60,
        path      => '/usr/sbin:/usr/bin:/sbin:/bin',
        before    => Class['neutron::plugins::ovs::opendaylight'],
      }
    }

    if hiera('opendaylight_features', 'odl-ovsdb-openstack') =~ /odl-vpnservice-openstack/ {
      $odl_tunneling_ip = hiera('neutron::agents::ml2::ovs::local_ip')
      $private_network = hiera('neutron_tenant_network')
      $cidr_arr = split($private_network, '/')
      $private_mask = $cidr_arr[1]
      $private_subnet = inline_template("<%= require 'ipaddr'; IPAddr.new('$private_network').mask('$private_mask') -%>")
      $odl_port = hiera('opendaylight_port')
      $file_setupTEPs = '/tmp/setup_TEPs.py'
      $astute_yaml = "network_metadata:
  vips:
    management:
      ipaddr: ${opendaylight_controller_ip}
opendaylight:
  rest_api_port: ${odl_port}
  bgpvpn_gateway: 11.0.0.254
private_network_range: ${private_subnet}/${private_mask}"

      file { '/etc/astute.yaml':
        content => $astute_yaml,
      }
      exec { 'setup_TEPs':
        # At the moment the connection between ovs and ODL is no HA if vpnfeature is activated
        command => "python $file_setupTEPs $opendaylight_controller_ip $odl_tunneling_ip $odl_ovsdb_iface",
        require => File['/etc/astute.yaml'],
        path => '/usr/local/bin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/sbin',
      }
    } elsif hiera('fdio', false) {
      $odl_username  = hiera('opendaylight_username')
      $odl_password  = hiera('opendaylight_password')
      $ctrlplane_interface = hiera('nic1')
      if ! $ctrlplane_interface { fail("Cannot map logical interface NIC1 to physical interface") }
      $vpp_ip = inline_template("<%= scope.lookupvar('::ipaddress_${ctrlplane_interface}') -%>")
      $fdio_data_template='{"node" : [{"node-id":"<%= @fqdn %>","netconf-node-topology:host":"<%= @vpp_ip %>","netconf-node-topology:port":"2830","netconf-node-topology:tcp-only":false,"netconf-node-topology:keepalive-delay":0,"netconf-node-topology:username":"<%= @odl_username %>","netconf-node-topology:password":"<%= @odl_password %>","netconf-node-topology:connection-timeout-millis":10000,"netconf-node-topology:default-request-timeout-millis":10000,"netconf-node-topology:max-connection-attempts":10,"netconf-node-topology:between-attempts-timeout-millis":10000,"netconf-node-topology:schema-cache-directory":"hcmount"}]}'
      $fdio_data = inline_template($fdio_data_template)
      $fdio_url = "http://${opendaylight_controller_ip}:${opendaylight_port}/restconf/config/network-topology:network-topology/network-topology:topology/topology-netconf"
      exec { 'VPP Mount into ODL':
        command   => "curl -o /dev/null --fail --silent -u ${odl_username}:${odl_password} ${fdio_url} -i -H 'Content-Type: application/json' --data \'${fdio_data}\' -X PUT",
        tries     => 5,
        try_sleep => 30,
        path      => '/usr/sbin:/usr/bin:/sbin:/bin',
      }

      # Setup honeycomb
      class { '::honeycomb':
        rest_port => '8182',
      }
    } else {
      class { '::neutron::plugins::ovs::opendaylight':
        tunnel_ip             => $private_ip,
        odl_username          => hiera('opendaylight_username'),
        odl_password          => hiera('opendaylight_password'),
        odl_check_url         => $opendaylight_url,
        odl_ovsdb_iface       => $odl_ovsdb_iface,
      }
    }
  } elsif 'onos_ml2' in hiera('neutron::plugins::ml2::mechanism_drivers') {
    $controller_ips = split(hiera('controller_node_ips'), ',')
    class { 'onos::ovs_computer':
      manager_ip => $controller_ips[0]
    }

  } else {
    
    # NOTE: this code won't live in puppet-neutron until Neutron OVS agent
    # can be gracefully restarted. See https://review.openstack.org/#/c/297211
    # In the meantime, it's safe to restart the agent on each change in neutron.conf,
    # because Puppet changes are supposed to be done during bootstrap and upgrades.
    # Some resource managed by Neutron_config (like messaging and logging options) require
    # a restart of OVS agent. This code does it.
    # In Newton, OVS agent will be able to be restarted gracefully so we'll drop the code
    # from here and fix it in puppet-neutron.
    Neutron_config<||> ~> Service['neutron-ovs-agent-service']

    include ::neutron::agents::ml2::ovs

    if 'cisco_n1kv' in hiera('neutron::plugins::ml2::mechanism_drivers') {
      class { '::neutron::agents::n1kv_vem':
        n1kv_source  => hiera('n1kv_vem_source', undef),
        n1kv_version => hiera('n1kv_vem_version', undef),
      }
    }

    if 'bsn_ml2' in hiera('neutron::plugins::ml2::mechanism_drivers') {
      include ::neutron::agents::bigswitch
    }
  }
}

neutron_config {
  'DEFAULT/host': value => $fqdn;
}

include ::ceilometer
include ::ceilometer::config
include ::ceilometer::agent::compute
include ::ceilometer::agent::auth

$snmpd_user = hiera('snmpd_readonly_user_name')
snmp::snmpv3_user { $snmpd_user:
  authtype => 'MD5',
  authpass => hiera('snmpd_readonly_user_password'),
}
class { '::snmp':
  agentaddress => ['udp:161','udp6:[::1]:161'],
  snmpd_config => [ join(['createUser ', hiera('snmpd_readonly_user_name'), ' MD5 "', hiera('snmpd_readonly_user_password'), '"']), join(['rouser ', hiera('snmpd_readonly_user_name')]), 'proc  cron', 'includeAllDisks  10%', 'master agentx', 'trapsink localhost public', 'iquerySecName internalUser', 'rouser internalUser', 'defaultMonitors yes', 'linkUpDownNotifications yes' ],
}

# Configure host for live migration
user { 'nova':
  shell => '/bin/bash'
}
file { '/etc/ssh/ssh_known_hosts':
  ensure => present,
  owner  => 'root',
  group  => 'root'
} ~>
# Add all overcloud nodes to known_hosts
exec { 'populate_ssh_known_hosts':
  command     => "for node in $(os-apply-config --key hosts --type raw --key-default '' | cut -d ' ' -f 1 | uniq); do if ! grep -q \$node /etc/ssh/ssh_known_hosts; then ssh-keyscan -t rsa \$node >> /etc/ssh/ssh_known_hosts; fi; done",
  provider    => 'shell',
  path        => ['/usr/bin', '/usr/sbin'],
  refreshonly => true,
}

hiera_include('compute_classes')
package_manifest{'/var/lib/tripleo/installed-packages/overcloud_compute': ensure => present}
