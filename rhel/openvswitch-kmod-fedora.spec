# Generated automatically -- do not modify!    -*- buffer-read-only: t -*-
# Spec file for Open vSwitch.

# Copyright (C) 2009, 2010, 2015, 2018 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

%global debug_package %{nil}

# Use the kversion macro such as
# RPMBUILD_OPT='-D "kversion 3.10.0-693.1.1.el7.x86_64 3.10.0-693.17.1.el7.x86_64"'
# to build package for mulitple kernel versions in the same package
# This only works for the following kernels.
#   - 3.10.0 major revision 327  (RHEL 7.2)
#   - 3.10.0 major revision 693  (RHEL 7.4)
#   - 3.10.0 major revision 957  (RHEL 7.6)
#   - 3.10.0 major revision 1062 (RHEL 7.7)
#   - 3.10.0 major revision 1101 (RHEL 7.8 Beta)
#   - 3.10.0 major revision 1127 (RHEL 7.8 GA)
#   - 3.10.0 major revision 1160 (RHEL 7.9 GA)
# By default, build against the current running kernel version
#%define kernel 3.1.5-1.fc16.x86_64
#define kernel %{kernel_source}
%{?kversion:%define kernel %kversion}

%{!?release_number:%define release_number 1}

Name: openvswitch-kmod
Summary: Open vSwitch Kernel Modules
Group: System Environment/Daemons
URL: http://www.openvswitch.org/
Vendor: OpenSource Security Ralf Spenneberg <ralf@os-s.net>
Version: 2.17.7

# The entire source code is ASL 2.0 except datapath/ which is GPLv2
License: GPLv2
Release: %{release_number}%{?dist}
Source: openvswitch-%{version}.tar.gz
#Source1: openvswitch-init
Buildroot: /tmp/openvswitch-xen-rpm
Provides: kmod-openvswitch
Obsoletes: kmod-openvswitch < %{version}-%{release}

%description
Open vSwitch provides standard network bridging functions augmented with
support for the OpenFlow protocol for remote per-flow control of
traffic. This package contains the kernel modules.

%prep
%setup -q -n openvswitch-%{version}

%build
for kv in %{kversion}; do
    mkdir -p _$kv
    (cd _$kv && /bin/cp -f ../configure . && %configure --srcdir=.. \
        --with-linux=/lib/modules/${kv}/build --enable-ssl %{_ovs_config_extra_flags})
    make %{_smp_mflags} -C _$kv/datapath/linux
done

%install
export INSTALL_MOD_DIR=extra/openvswitch
rm -rf $RPM_BUILD_ROOT
for kv in %{kversion}; do
    make INSTALL_MOD_PATH=$RPM_BUILD_ROOT -C _$kv/datapath/linux modules_install
done
mkdir -p $RPM_BUILD_ROOT/etc/depmod.d
for kv in %{kversion}; do
    for module in $RPM_BUILD_ROOT/lib/modules/${kv}/extra/openvswitch/*.ko
    do
        modname="$(basename ${module})"
        grep -qsPo "^\s*override ${modname%.ko} \* extra\/openvwitch" \
            $RPM_BUILD_ROOT/etc/depmod.d/kmod-openvswitch.conf || \
            echo "override ${modname%.ko} * extra/openvswitch" >> \
            $RPM_BUILD_ROOT/etc/depmod.d/kmod-openvswitch.conf
        grep -qsPo "^\s*override ${modname%.ko} \* weak-updates\/openvwitch" \
            $RPM_BUILD_ROOT/etc/depmod.d/kmod-openvswitch.conf || \
            echo "override ${modname%.ko} * weak-updates/openvswitch" >> \
            $RPM_BUILD_ROOT/etc/depmod.d/kmod-openvswitch.conf
    done
done
install -d -m 0755 $RPM_BUILD_ROOT/usr/share/openvswitch/scripts
install -p -m 0755 rhel/usr_share_openvswitch_scripts_ovs-kmod-manage.sh \
    $RPM_BUILD_ROOT%{_datadir}/openvswitch/scripts/ovs-kmod-manage.sh

%clean
rm -rf $RPM_BUILD_ROOT

%post
current_kernel=$(uname -r)
IFS='.\|-' read mainline_major mainline_minor mainline_patch major_rev \
    minor_rev _extra <<<"${current_kernel}"
# echo mainline_major=$mainline_major mainline_minor=$mainline_minor \
# mainline_patch=$mainline_patch major_rev=$major_rev minor_rev=$minor_rev
if grep -qs "suse" /etc/os-release; then
    # For SLES or OpenSUSE
    if [ -x "%{_datadir}/openvswitch/scripts/ovs-kmod-manage.sh" ]; then
        %{_datadir}/openvswitch/scripts/ovs-kmod-manage.sh
    fi
elif [ "$mainline_major" = "3" ] && [ "$mainline_minor" = "10" ] &&
     { [ "$major_rev" = "327" ] || [ "$major_rev" = "693" ] || \
       [ "$major_rev" = "957" ] || [ "$major_rev" == "1062" ] || \
       [ "$major_rev" = "1101" ] || [ "$major_rev" = "1127" ] || \
       [ "$major_rev" = "1160" ] ; }; then
    # For RHEL 7.2, 7.4, 7.6, 7.7, 7.8 and 7.9
    if [ -x "%{_datadir}/openvswitch/scripts/ovs-kmod-manage.sh" ]; then
        %{_datadir}/openvswitch/scripts/ovs-kmod-manage.sh
    fi
else
    # Ensure that modprobe will find our modules.
    for k in $(cd /lib/modules && /bin/ls); do
        [ -d "/lib/modules/$k/kernel/" ] && /sbin/depmod -a "$k"
    done
    if [ -x "/sbin/weak-modules" ]; then
        for m in openvswitch vport-gre vport-stt vport-geneve \
                 vport-lisp vport-vxlan; do
            echo "/lib/modules/%{kernel}/extra/openvswitch/$m.ko"
        done | /sbin/weak-modules --add-modules
    fi
fi

%postun
if [ "$1" = 0 ]; then  # Erase, not upgrade
    for kname in `ls -d /lib/modules/*`
do
    rm -rf $kname/weak-updates/openvswitch
done
fi
/sbin/depmod -a

%posttrans
# The upgrade path from the older kmod-openvswitch SysV package to
# the newer openvswitch-kmod systemd package will end up removing
# the symlinks to the weak-updates/openvswitch drivers because of
# it's %postun section.  We add this section to handle that case.
if [ -x "%{_datadir}/openvswitch/scripts/ovs-kmod-manage.sh" ]; then
    %{_datadir}/openvswitch/scripts/ovs-kmod-manage.sh
fi

%files
%defattr(0644,root,root)
/lib/modules/*/extra/openvswitch/*.ko
/etc/depmod.d/kmod-openvswitch.conf
%exclude /lib/modules/*/modules.*
%attr(755,root,root) %{_datadir}/openvswitch/scripts/ovs-kmod-manage.sh

%changelog
* Wed Sep 21 2011 Kyle Mestery <kmestery@cisco.com>
- Updated for F15
* Wed Jan 12 2011 Ralf Spenneberg <ralf@os-s.net>
- First build on F14
