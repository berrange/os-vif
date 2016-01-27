#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from os_vif import objects
from os_vif import plugin

from oslo_concurrency import processutils

from vif_plug_ovs import exception
from vif_plug_ovs import linux_net


class OvsHybridPlugin(plugin.PluginBase):
    """
    An OVS VIF type that uses a pair of devices in order to allow
    security group rules to be applied to traffic coming in or out of
    a virtual machine.
    """

    NIC_NAME_LEN = 14

    def __init__(self, **config):
        self.network_device_mtu = config.get('network_device_mtu', 1500)
        self.ovs_vsctl_timeout = config.get('ovs_vsctl_timeout', 120)

    @staticmethod
    def get_veth_pair_names(vif):
        iface_id = vif.id
        return (("qvb%s" % iface_id)[:OvsHybridPlugin.NIC_NAME_LEN],
                ("qvo%s" % iface_id)[:OvsHybridPlugin.NIC_NAME_LEN])

    def describe(self):
        return plugin.PluginInfo(
            [
                plugin.PluginVIFInfo(
                    objects.vif.VIFBridge,
                    "1.0", "1.0")
            ])

    def plug(self, vif, instance_info):
        """Plug using hybrid strategy

        Create a per-VIF linux bridge, then link that bridge to the OVS
        integration bridge via a veth device, setting up the other end
        of the veth device just like a normal OVS port. Then boot the
        VIF on the linux bridge using standard libvirt mechanisms.
        """

        if not hasattr(vif, "port_profile"):
            raise exception.MissingPortProfile()
        if not isinstance(vif.port_profile,
                          objects.vif.VIFPortProfileOpenVSwitch):
            raise exception.WrongPortProfile(
                profile=vif.port_profile.__class__.__name__)

        v1_name, v2_name = self.get_veth_pair_names(vif)

        if not linux_net.device_exists(vif.bridge_name):
            processutils.execute('brctl', 'addbr', vif.bridge_name,
                                 run_as_root=True)
            processutils.execute('brctl', 'setfd', vif.bridge_name, 0,
                                 run_as_root=True)
            processutils.execute('brctl', 'stp', vif.bridge_name, 'off',
                                 run_as_root=True)
            syspath = '/sys/class/net/%s/bridge/multicast_snooping'
            syspath = syspath % vif.bridge_name
            processutils.execute('tee', syspath, process_input='0',
                                 check_exit_code=[0, 1],
                                 run_as_root=True)

        if not linux_net.device_exists(v2_name):
            linux_net.create_veth_pair(v1_name, v2_name,
                                       self.network_device_mtu)
            processutils.execute('ip', 'link', 'set', vif.bridge_name, 'up',
                                 run_as_root=True)
            processutils.execute('brctl', 'addif', vif.bridge_name, v1_name,
                                 run_as_root=True)
            linux_net.create_ovs_vif_port(vif.network.bridge,
                                          v2_name,
                                          vif.port_profile.interface_id,
                                          vif.address, instance_info.uuid)

    def unplug(self, vif, instance_info):
        """UnPlug using hybrid strategy

        Unhook port from OVS, unhook port from bridge, delete
        bridge, and delete both veth devices.
        """
        if not hasattr(vif, "port_profile"):
            raise exception.MissingPortProfile()
        if not isinstance(vif.port_profile,
                          objects.vif.VIFPortProfileOpenVSwitch):
            raise exception.WrongPortProfile(
                profile=vif.port_profile.__class__.__name__)

        v1_name, v2_name = self.get_veth_pair_names(vif)

        if linux_net.device_exists(vif.bridge_name):
            processutils.execute('brctl', 'delif', vif.bridge_name, v1_name,
                                 run_as_root=True)
            processutils.execute('ip', 'link', 'set', vif.bridge_name, 'down',
                                 run_as_root=True)
            processutils.execute('brctl', 'delbr', vif.bridge_name,
                                 run_as_root=True)

        linux_net.delete_ovs_vif_port(vif.network.bridge, v2_name)
