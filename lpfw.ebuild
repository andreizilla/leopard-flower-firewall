# Copyright 1999-2011 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

DESCRIPTION="LeopardFlower is a per-application firewall."
HOMEPAGE="http://leopardflower.sourceforge.net"
SRC_URI="mirror://sourceforge/projects/leopardflower/Source/{P}.tar.bz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~x86"
EAPI=2
IUSE="sysvipc syslog"

DEPEND="net-libs/libnetfilter_conntrack
		net-libs/libnetfilter_queue"
		
RDEPEND="${DEPEND}
		net-firewall/iptables"

pkg_setup() {
	if ! linux_config_exists; then
		eerror "Kernel configuration file doesn't exist."
		eerror "Unable to check if kernel is properly configured."
	elif ! linux_chkconfig_present NETFILTER ; then
		eerror "NETFILTER isn't enabled in the kernel"
	elif ! linux_c hkconfig_present NF_CONNTRACK ; then
		eerror "NF_CONNTRACK isn't enabled in the kernel"
	elif ! linux_chkconfig_present NF_CONNTRACK_MARK ; then
		eerror "NF_CONNTRACK_MARK isn't enabled in the kernel"
	elif ! linux_chkconfig_present NETFILTER_XT_TARGET_NFQUEUE ; then
		eerror "NETFILTER_XT_TARGET_NFQUEUE isn't enabled in the kernel"
	elif ! linux_chkconfig_present NETFILTER_XT_MATCH_STATE ; then
		eerror "NETFILTER_XT_MATCH_STATE isn't enabled in the kernel"
	elif ! linux_chkconfig_present PROC_FS ; then
		eerror "PROC_FS isn't enabled in the kernel"						
	elif use sysvipc ; then
		if ! linux_chkconfig_present SYSVIPC ; then
			eerror "SYSVIPC isn't enabled in the kernel"
		fi
	fi
	
	if ! use sysvipc ; then
		eerror "sysvipc USE flag is disabled. This means that you will"
		error "not be able to use a frontend"
	fi
}

src_configure(){
	econf \
		$(use_enable sysvipc) \
		$(use_enable syslog)
}

src_compile() {
    emake || die
}	

src_install() {
    emake DESTDIR="${D}" install || die "make install failed"
    dodoc README INSTALL CHANGELOG|| die
}
