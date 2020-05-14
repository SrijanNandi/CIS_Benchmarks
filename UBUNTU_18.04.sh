#!/bin/bash

# CIS Hardening Script for Ubuntu Server 18.04 LTS
# Srijan Nandi

##############################################################################################################

# Check if running with root User

check_root(){
if [ $EUID -ne 0 ]; then
    echo "Permission Denied"
    echo "Can only be run by root"
    exit
else
    :
fi
}

check_root

##############################################################################################################

# Ensure updates, patches, and additional security software are installed
universe_repo_dep() {
OUTPUT=`add-apt-repository universe`

if [[ $OUTPUT = "'universe' distribution component is already enabled for all sources." ]]; then
    :
else
    add-apt-repository universe 2>&1 >/dev/null
fi
}

system_update() {
apt-get update 2>&1 >/dev/null && apt-get -y upgrade 2>&1 >/dev/null && apt-get -y dist-upgrade 2>&1 >/dev/null && apt-get -y autoremove 2>&1 >/dev/null && apt-get -y autoclean 2>&1 >/dev/null
}

universe_repo_dep
system_update

##############################################################################################################

# Configure TimeZone
config_timezone(){
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m We will now Configure the TimeZone"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   sleep 10
   dpkg-reconfigure tzdata
}

##############################################################################################################

# Disabling unused filesystem

ROOT_DEV_NAME=`lsblk -i | grep '/' | awk '{print $1}'`

FILE_SYS_NAME=`blkid -o value -s TYPE /dev/$ROOT_DEV_NAME`
echo $FILE_SYS_NAME

unused_filesystems(){
   clear
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Disabling Unused FileSystems"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   #spinner
   echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
   echo " OK"
}

unused_filesystems

##############################################################################################################

# Ensure permissions on bootloader config are configured (Scored)

set_grubpassword(){
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m GRUB Bootloader Password"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo "It is recommended to set a password on GRUB bootloader to prevent altering boot configuration (e.g. boot in single user mode without password)"
  echo ""
  echo -n " Do you want to set a GRUB Bootloader Password? (y/n): " ; read grub_answer
  if [ "$grub_answer" == "y" ]; then
    grub-mkpasswd-pbkdf2 | tee grubpassword.tmp
    grubpassword=$(cat grubpassword.tmp | sed -e '1,2d' | cut -d ' ' -f7)
    echo " set superusers="root" " >> /etc/grub.d/40_custom
    echo " password_pbkdf2 root $grubpassword " >> /etc/grub.d/40_custom
    rm grubpassword.tmp
    update-grub
    echo "On every boot enter root user and the password you just set"
    echo "OK"
  else
    echo "OK"
  fi

echo -e ""
echo -e "Securing Boot Settings"
#spinner
sleep 2
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
}    

set_grubpassword

##############################################################################################################

# Ensure echoping, time, rsh, talk, telnet, tftp, xinetd, Ubuntu-Desktop, Avahi, rsync, cups, DHCPD, LDAP Server, LDAP Client, RPC, NFS, SNMP, FTP are disabled and removed

remove_unwanted_modules() {
apt-get -y remove --purge echoping time rsh-* talk telnet tftp xinetd xserver-xorg-core 'x11-*' ubuntu-desktop unity gnome-shell lightdm avahi-* rsync cups cups-* isc-dhcp-server ldap-utils ldap-auth-client rpcbind cipux-rpc-tools rpcbind nfs-kernel-server nfs-kernel-server nfs-common portmap snmp vsftpd ftp 2>&1 >/dev/null

apt-get -y autoremove 2>&1 >/dev/null && apt-get -y autoclean 2>&1 >/dev/null
}

remove_unwanted_modules

##############################################################################################################

SYSCTL_FILE="/etc/sysctl.conf"

if [ -f $SYSCTL_FILE ]; then
    cp -r -p $SYSCTL_FILE $SYSCTL_FILE.`date +%Y.%m.%d.%H.%M.%S`.bak
    cat << 'EOF' > $SYSCTL_FILE
# Kernel sysctl configuration file for Ubuntu
# Modified by Srijan Nandi
#

# Controls IP packet forwarding
net.ipv4.ip_forward = 0

# Controls source route verification
net.ipv4.conf.default.rp_filter = 1

# Do not accept source routing
net.ipv4.conf.default.accept_source_route = 0

# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0

# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
kernel.core_uses_pid = 1

# Controls the use of TCP syncookies
net.ipv4.tcp_syncookies = 1

# Disable netfilter on bridges.
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0

# Controls the default maxmimum size of a mesage queue
kernel.msgmnb = 65536

# Controls the maximum size of a message, in bytes
kernel.msgmax = 65536

# Controls the maximum shared segment size, in bytes
kernel.shmmax = 68719476736

# Controls the maximum number of shared memory segments, in pages
kernel.shmall = 4294967296

######### GENERAL SECURITY OPTIONS ################

# Automatically Reboot Server in 30 Seconds after a Kernel Panic
vm.panic_on_oom = 1
kernel.panic = 30
kernel.panic_on_oops = 30

# Enable ExecShield
kernel.exec-shield = 1

kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2

########## COMMUNICATIONS SECURITY ##############
# No Redirections
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Do not Accept Packets with SRR
net.ipv4.conf.all.accept_source_route = 0

# Do not accept Redirections
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.secure_redirects = 0
net.ipv6.conf.default.secure_redirects = 0

# Do not Accept source routed Packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable Packets Forwarding
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

# Log Suspicious Packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore ICMP ECHO or TIMESTAMP sent by broadcast/multicast
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_timestamps = 0

# Protect Against 'syn flood attack'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Enable Reverse Source Validation (Protects Against IP Spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore Bogus Error Response
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reduce KeepAlive
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

#Ensure IPv6 router advertisement are not accepted
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

fs.suid_dumpable = 0
EOF

fi

##############################################################################################################

# Check if ufw is installed
OUTPUT=`systemctl status ufw 2>&1`

if [[ $OUTPUT = "Unit ufw.service could not be found." ]]; then
    echo "uf is not INSTALLED"
else
    systemctl stop ufw 2>&1 >/dev/null
    apt-get -y remove --purge ufw 2>&1 >/dev/null
fi

# Check if firewalld is installed
OUTPUT=`systemctl status firewalld 2>&1`

if [[ $OUTPUT = "Unit firewalld.service could not be found." ]]; then
    echo "firewalld is not INSTALLED"
else
    systemctl stop firewalld 2>&1 >/dev/null
    apt-get -y remove --purge firewalld 2>&1 >/dev/null
fi

# Function to declare iptables rules
iptables_rules() {
# Flush Iptables rules
iptables -F

# Discard outbound invalid Packets
iptables -A OUTPUT -m state --state INVALID -j DROP

# Ensure established outbound connections are configured
iptables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Ensure loopback traffic is configured in OUTPUT Chain
iptables -A OUTPUT -o lo -j ACCEPT

# Discard forward invalid Packets
iptables -A FORWARD -m state --state INVALID -j DROP

# Ensure established forwarded connections are configured
iptables -A FORWARD -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Stop PING of Death attack
iptables -N PING_OF_DEATH
iptables -A PING_OF_DEATH -j DROP
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request -m hashlimit --hashlimit 1/s --hashlimit-burst 10 --hashlimit-htable-expire 300000 --hashlimit-mode srcip --hashlimit-name t_PING_OF_DEATH -j RETURN
iptables -A INPUT -p icmp --icmp-type echo-request -j PING_OF_DEATH

# Stop port scanning, SYN flood attacks, invalid packets, malformed XMAS packets, NULL packets, etc.
iptables -N PORTSCAN
iptables -A PORTSCAN -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A PORTSCAN -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A PORTSCAN -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -A PORTSCAN -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A PORTSCAN -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A PORTSCAN -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A PORTSCAN -p tcp --tcp-flags ALL ALL -j DROP
iptables -A PORTSCAN -p tcp --tcp-flags ALL NONE -j DROP
iptables -A PORTSCAN -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A PORTSCAN -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -A PORTSCAN -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A INPUT -p tcp -j PORTSCAN

# Invalid Traffic
iptables -A INPUT -f -j DROP
iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# Drop Spoofing attacks
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

# Stop Masked Attackes
iptables -A INPUT -p icmp --icmp-type 13 -j DROP
iptables -A INPUT -p icmp --icmp-type 17 -j DROP
iptables -A INPUT -p icmp --icmp-type 14 -j DROP

# Discard inbound invalid Packets
iptables -A INPUT -m state --state INVALID -j DROP

# Ensure outbound and established connections are configured
iptables -A INPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# Ensure loopback traffic is configured
iptables -A INPUT -i lo -j ACCEPT

# Limit ICMP Connections
iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT

# Open inbound ssh connections
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 2224 -m conntrack --ctstate NEW -j ACCEPT

# Default deny Firewall policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
}


# Install iptables-persistent
OUTPUT=`systemctl status netfilter-persistent`
IPTABLES_FILE="/etc/iptables/rules.v4"

if [[ $OUTPUT = "active" ]] && [ -f $IPTABLES_FILE ]; then
    :
else
    apt-get -y install iptables-persistent netfilter-persistent 2>&1 >/dev/null
    iptables_rules
fi

##############################################################################################################

# Disabling Uncommon Network Protocols

uncommon_netprotocols() {
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Disabling Uncommon Network Protocols"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   #spinner
   echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "OK"
}

uncommon_netprotocols

##############################################################################################################

# SSH Server Configuration and hardening

OUTPUT=`stat /etc/ssh/sshd_config`
OUTPUT_1=`stat /etc/ssh/sshd_config | sed -n '4p' | awk '{print $3,$6}' | sed 's/)//g'`
OUTPUT_2=`stat /etc/ssh/sshd_config | sed -n '4p' | awk '{print $7,$10}' | sed 's/)//g'`

if [[ $OUTPUT_1 = "Uid: root"  ]] && [[ $OUTPUT_2 = "Gid: root"  ]]; then
    echo "SSHD Permissions are set.............OK"
else
    echo "$OUTPUT"
    chown root:root /etc/ssh/sshd_config
    chmod og-rwx /etc/ssh/sshd_config
fi

OUTPUT=`sshd -T | grep -Ei '^\s*protocol\s+(1|1\s*,\s*2|2\s*,\s*1)\s*'`

if [[ $? -eq 0 ]]; then
    echo "SSH Protocol is set to v2.................OK"
else
    usermod -g 0 root
fi

echo ""
echo -n " Do you want to set SSH Port to 2224? (y/n): " ; read ssh_port_answer
    if [ "$ssh_port_answer" == "y" ]; then
        sed -i 's/#Port 22/Port 2224/' /etc/ssh/sshd_config
    fi

sed -i 's/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config

OUTPUT=`sshd -T | grep loglevel | awk '{print $2}'`

if [[ $OUTPUT = "INFO" ]] || [[ $OUTPUT = "VERBOSE" ]]; then
    echo "LogLevel is appropriate..................OK"
else
    sed -i 's/#LogLevel INFO/LogLevel INFO/' /etc/ssh/sshd_config
fi

OUTPUT=`sshd -T | grep x11forwarding | awk '{print $2}'`
OUTPUT_1=`sed -n '/X11Forwarding/p' /etc/ssh/sshd_config | sed -n '1p'`

if [[ $OUTPUT = "no" ]]; then
    echo "SSH X11 forwarding is disabled..................OK"
else
    if [[ $OUTPUT_1 = "X11Forwarding yes" ]]; then
        sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    elif [[ $OUTPUT_1 = "#X11Forwarding yes" ]]; then
        sed -i 's/#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    elif [[ $OUTPUT_1 = "#X11Forwarding no" ]]; then
        sed -i 's/#X11Forwarding no/X11Forwarding no/' /etc/ssh/sshd_config
    fi
fi

OUTPUT=`sshd -T | grep maxauthtries | awk '{print $2}'`
INT="4"

if [ "$OUTPUT" -le "$INT" ]; then
    echo "SSH MaxAuthTries is set to 4 or less..................OK"
else
    sed -i "s/$OUTPUT/4/g" /etc/ssh/sshd_config
fi

OUTPUT=`sshd -T | grep ignorerhosts | awk '{print $2}'`
OUTPUT_1=`sed -n '/IgnoreRhosts/p' /etc/ssh/sshd_config | sed -n '1p'`

if [[ $OUTPUT = "yes" ]]; then
    echo "SSH IgnoreRhosts is enabled..................OK"
else
    if [[ $OUTPUT_1 = "IgnoreRhosts no" ]]; then
        sed -i 's/IgnoreRhosts no/IgnoreRhosts yes/' /etc/ssh/sshd_config
    elif [[ $OUTPUT_1 = "#IgnoreRhosts no" ]]; then
        sed -i 's/#IgnoreRhosts no/IgnoreRhosts yes/' /etc/ssh/sshd_config
    elif [[ $OUTPUT_1 = "#IgnoreRhosts yes" ]]; then
        sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/' /etc/ssh/sshd_config
    fi
fi

OUTPUT=`sshd -T | grep hostbasedauthentication | awk '{print $2}'`
OUTPUT_1=`sed -n '/HostbasedAuthentication/p' /etc/ssh/sshd_config | sed -n '1p'`

if [[ $OUTPUT = "no" ]]; then
    echo "SSH HostbasedAuthentication is disabled..................OK"
else
    if [[ $OUTPUT_1 = "HostbasedAuthentication yes" ]]; then
        sed -i 's/HostbasedAuthentication yes/HostbasedAuthentication no/' /etc/ssh/sshd_config
    elif [[ $OUTPUT_1 = "#HostbasedAuthentication no" ]]; then
        sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/' /etc/ssh/sshd_config
    elif [[ $OUTPUT_1 = "#HostbasedAuthentication yes" ]]; then
        sed -i 's/#HostbasedAuthentication yes/HostbasedAuthentication no/' /etc/ssh/sshd_config
    fi
fi

OUTPUT=`sed -n '/PermitRootLogin/p' /etc/ssh/sshd_config | sed -n '1p'`

if [[ $OUTPUT = "PermitRootLogin no" ]]; then
    echo "SSH root login is disabled..................OK"
else
    if [[ $OUTPUT = "PermitRootLogin yes" ]]; then
        sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    elif [[ $OUTPUT = "#PermitRootLogin no" ]]; then
        sed -i 's/#PermitRootLogin no/PermitRootLogin no/' /etc/ssh/sshd_config
    elif [[ $OUTPUT = "#PermitRootLogin yes" ]]; then
        sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    fi
fi

OUTPUT=`sed -n '/PermitEmptyPasswords/p' /etc/ssh/sshd_config | sed -n '1p'`

if [[ $OUTPUT = "PermitEmptyPasswords no" ]]; then
    echo "SSH PermitEmptyPasswords is disabled..................OK"
else
    if [[ $OUTPUT = "PermitEmptyPasswords yes" ]]; then
        sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    elif [[ $OUTPUT = "#PermitEmptyPasswords no" ]]; then
        sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    elif [[ $OUTPUT = "#PermitEmptyPasswords yes" ]]; then
        sed -i 's/#PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    fi
fi

OUTPUT=`sed -n '/PermitUserEnvironment/p' /etc/ssh/sshd_config | sed -n '1p'`

if [[ $OUTPUT = "PermitUserEnvironment no" ]]; then
    echo "SSH PermitUserEnvironment is disabled..................OK"
else
    if [[ $OUTPUT = "PermitUserEnvironment yes" ]]; then
        sed -i 's/PermitUserEnvironment yes/PermitUserEnvironment no/' /etc/ssh/sshd_config
    elif [[ $OUTPUT = "#PermitUserEnvironment no" ]]; then
        sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/' /etc/ssh/sshd_config
    elif [[ $OUTPUT = "#PermitUserEnvironment yes" ]]; then
        sed -i 's/#PermitUserEnvironment yes/PermitUserEnvironment no/' /etc/ssh/sshd_config
    fi
fi

OUTPUT=`sed -n '/UsePAM/p' /etc/ssh/sshd_config | sed -n '1p'`

if [[ $OUTPUT = "UsePAM yes" ]]; then
    echo "SSH PAM is enabled..................OK"
else
    if [[ $OUTPUT = "UsePAM no" ]]; then
        sed -i 's/UsePAM no/UsePAM yes/' /etc/ssh/sshd_config
    elif [[ $OUTPUT = "#UsePAM no" ]]; then
        sed -i 's/#UsePAM no/UsePAM yes/' /etc/ssh/sshd_config
    elif [[ $OUTPUT = "#UsePAM yes" ]]; then
        sed -i 's/#UsePAM yes/UsePAM yes/' /etc/ssh/sshd_config
    fi
fi

OUTPUT=`sed -n '/AllowTcpForwarding/p' /etc/ssh/sshd_config | sed -n '1p'`

if [[ $OUTPUT = "AllowTcpForwarding yes" ]]; then
    echo "SSH AllowTcpForwarding is disabled..................OK"
else
    if [[ $OUTPUT = "AllowTcpForwarding no" ]]; then
        sed -i 's/AllowTcpForwarding no/AllowTcpForwarding yes/' /etc/ssh/sshd_config
    elif [[ $OUTPUT = "#AllowTcpForwarding no" ]]; then
        sed -i 's/#AllowTcpForwarding no/AllowTcpForwarding yes/' /etc/ssh/sshd_config
    elif [[ $OUTPUT = "#AllowTcpForwarding yes" ]]; then
        sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding yes/' /etc/ssh/sshd_config
    fi
fi

##############################################################################################################

# Ensure system accounts are non-login (Scored)

OUTPUT_1=`awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print}' /etc/passwd`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print $1}' /etc/passwd | while read -r user; do usermod -s "$(which nologin)" "$user"; done
fi

OUTPUT_2=`awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}'`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}' | while read -r user; do usermod -L "$user"; done
fi


##############################################################################################################

# Additional Hardening Steps
additional_hardening(){
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Running additional Hardening Steps"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Running Additional Hardening Steps...."
    #spinner
    echo tty1 > /etc/securetty
    chmod 0600 /etc/securetty
    chmod 700 /root
    chmod 600 /boot/grub/grub.cfg
    echo ""
    echo " Securing Cron "
    #spinner
    touch /etc/cron.allow
    chmod 600 /etc/cron.allow
    awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
}

additional_hardening

##############################################################################################################

# Ensure sticky bit is set on all world-writable directories
WWD=`df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null`

if [[ $? -eq 0 ]]; then
    echo "Sticky bit is set on all world-writable directories"
else
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'
fi

##############################################################################################################

#  Disabling Automounting
OUPUT=`dpkg -s autofs 2>&1 | head -n 1`

if [[ $OUTPUT = "dpkg-query: package 'autofs' is not installed and no information is available" ]]; then
    echo "Autofs is not installed - All OK"
else
    apt purge autofs > /dev/null 2>&1
fi

##############################################################################################################

# Ensure default group for the root account is GID 0
OUTPUT=`grep "^root:" /etc/passwd | cut -f4 -d:`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    usermod -g 0 root
fi

##############################################################################################################

# Ensure permissions on /etc/passwd are configured
OUTPUT=`stat /etc/passwd`
OUTPUT_1=`stat /etc/passwd | sed -n '4p' | awk '{print $3,$6}' | sed 's/)//g'`
OUTPUT_2=`stat /etc/passwd | sed -n '4p' | awk '{print $7,$10}' | sed 's/)//g'`

if [[ $OUTPUT_1 = "Uid: root"  ]] && [[ $OUTPUT_2 = "Gid: root"  ]]; then
    echo "OK"
else
    echo "$OUTPUT"
    chown root:root /etc/passwd
    chmod u-x,go-wx /etc/passwd-
fi

##############################################################################################################

# Ensure permissions on /etc/gshadow- are configured
OUTPUT=`stat /etc/gshadow-`
OUTPUT_1=`stat /etc/gshadow- | sed -n '4p' | awk '{print $3,$6}' | sed 's/)//g'`
OUTPUT_2=`stat /etc/gshadow- | sed -n '4p' | awk '{print $7,$10}' | sed 's/)//g'`

if [[ $OUTPUT_1 = "Uid: root"  ]] && [[ $OUTPUT_2 = "Gid: shadow"  ]]; then
    echo "OK"
else
    echo "$OUTPUT"
    chown root:shadow /etc/gshadow-
    chmod g-wx,o-rwx /etc/gshadow-
fi

##############################################################################################################

# Ensure permissions on /etc/shadow are configured
OUTPUT=`stat /etc/shadow`
OUTPUT_1=`stat /etc/shadow | sed -n '4p' | awk '{print $3,$6}' | sed 's/)//g'`
OUTPUT_2=`stat /etc/shadow | sed -n '4p' | awk '{print $7,$10}' | sed 's/)//g'`

if [[ $OUTPUT_1 = "Uid: root"  ]] && [[ $OUTPUT_2 = "Gid: shadow"  ]]; then
    echo "OK"
else
    echo "$OUTPUT"
    chown root:shadow /etc/shadow
    chown root:shadow /etc/shadow
fi

##############################################################################################################

# Ensure permissions on /etc/group are configured
OUTPUT=`stat /etc/group`
OUTPUT_1=`stat /etc/group | sed -n '4p' | awk '{print $3,$6}' | sed 's/)//g'`
OUTPUT_2=`stat /etc/group | sed -n '4p' | awk '{print $7,$10}' | sed 's/)//g'`

if [[ $OUTPUT_1 = "Uid: root"  ]] && [[ $OUTPUT_2 = "Gid: root"  ]]; then
    echo "OK"
else
    echo "$OUTPUT"
    chown root:root /etc/group
    cchmod 644 /etc/group
fi

##############################################################################################################

# Ensure permissions on /etc/passwd- are configured
OUTPUT=`stat /etc/passwd-`
OUTPUT_1=`stat /etc/passwd- | sed -n '4p' | awk '{print $3,$6}' | sed 's/)//g'`
OUTPUT_2=`stat /etc/passwd- | sed -n '4p' | awk '{print $7,$10}' | sed 's/)//g'`

if [[ $OUTPUT_1 = "Uid: root"  ]] && [[ $OUTPUT_2 = "Gid: root"  ]]; then
    echo "OK"
else
    echo "$OUTPUT"
    chown root:root /etc/passwd-
    chmod u-x,go-rwx /etc/passwd-
fi

##############################################################################################################

# Ensure permissions on /etc/shadow- are configured
OUTPUT=`stat /etc/shadow-`
OUTPUT_1=`stat /etc/shadow- | sed -n '4p' | awk '{print $3,$6}' | sed 's/)//g'`
OUTPUT_2=`stat /etc/shadow- | sed -n '4p' | awk '{print $7,$10}' | sed 's/)//g'`

if [[ $OUTPUT_1 = "Uid: root"  ]] && [[ $OUTPUT_2 = "Gid: shadow"  ]]; then
    echo "OK"
else
    echo "$OUTPUT"
    chown root:shadow /etc/shadow-
    chmod u-x,go-rwx /etc/shadow-
fi

##############################################################################################################

# Ensure permissions on /etc/group- are configured
OUTPUT=`stat /etc/group-`
OUTPUT_1=`stat /etc/group- | sed -n '4p' | awk '{print $3,$6}' | sed 's/)//g'`
OUTPUT_2=`stat /etc/group- | sed -n '4p' | awk '{print $7,$10}' | sed 's/)//g'`

if [[ $OUTPUT_1 = "Uid: root"  ]] && [[ $OUTPUT_2 = "Gid: root"  ]]; then
    echo "OK"
else
    echo "$OUTPUT"
    chown root:root /etc/group-
    chmod u-x,go-wx /etc/group-
fi

##############################################################################################################

# Ensure permissions on /etc/gshadow are configured
OUTPUT=`stat /etc/gshadow`
OUTPUT_1=`stat /etc/gshadow | sed -n '4p' | awk '{print $3,$6}' | sed 's/)//g'`
OUTPUT_2=`stat /etc/gshadow | sed -n '4p' | awk '{print $7,$10}' | sed 's/)//g'`

if [[ $OUTPUT_1 = "Uid: root"  ]] && [[ $OUTPUT_2 = "Gid: shadow"  ]]; then
    echo "OK"
else
    echo "$OUTPUT"
    chown root:shadow /etc/gshadow
    chmod o-rwx,g-wx /etc/gshadow
fi

##############################################################################################################

# Ensure no world writable files exist
OUTPUT=`df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensure no unowned files or directories exist
OUTPUT=`df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring root PATH Integrity
OUTPUT=`for x in $(echo "$PATH" | tr ":" " ") ; do if [ -d "$x" ] ; then ls -ldH "$x" | awk '
$9 == "." {print "PATH contains current working directory (.)"}
$3 != "root" {print $9, "is not owned by root"}
substr($1,6,1) != "-" {print $9, "is group writable"}
substr($1,9,1) != "-" {print $9, "is world writable"}'; else echo "$x is not a directory"; fi; done`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring password fields are not empty (
OUTPUT=`awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring all users' home directories exist
OUTPUT=`grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do if [ ! -d "$dir" ]; then echo "The home directory $dir of user $user does not exist."; fi; done`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring no legacy "+" entries exist in /etc/group
OUTPUT=`grep '^\+:' /etc/group`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring root is the only UID 0 account
OUTPUT=` awk -F: '($3 == 0) { print $1 }' /etc/passwd`

if [[ $OUTPUT = "root" ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring users own their home directories
OUTPUT=`grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do if [ ! -d "$dir" ]; then echo "The home directory \"$dir\" of user $user does not exist." ; else owner=$(stat -L -c "%U" "$dir"); if [ "$owner" != "$user" ]; then echo "The home directory \"$dir\" of user $user is owned by $owner."; fi; fi; done`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring users' dot files are not group or world writable
OUTPUT=`grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do if [ ! -d "$dir" ]; then echo "The home directory \"$dir\" of user \"$user\" does not exist."; else for file in "$dir"/.[A-Za-z0-9]*; do if [ ! -h "$file" ] && [ -f "$file" ]; then fileperm="$(ls -ld "$file" | cut -f1 -d" ")"; if [ "$(echo "$fileperm" | cut -c6)" != "-" ]; then echo "Group Write permission set on file $file"; fi; if [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then echo "Other Write permission set on file \"$file\""; fi; fi; done; fi; done`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring no users have .forward files
OUTPUT=`grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do if [ ! -d "$dir" ]; then echo "The home directory ($dir) of user $user does not exist."; else if [ ! -h "$dir/.forward" ] && [ -f "$dir/.forward" ]; then echo ".forward file \"$dir/.forward\" exists"; fi fi; done`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring no users have .netrc files
OUTPUT=`grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do if [ ! -d "$dir" ]; then echo "The home directory \"$dir\" of user \"$user\" does not exist." ; else if [ ! -h "$dir/.netrc" ] && [ -f "$dir/.netrc" ]; then echo ".netrc file \"$dir/.netrc\" exists"; fi; fi; done`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring users' .netrc Files are not group or world accessible
OUTPUT=`grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do if [ ! -d "$dir" ]; then echo "The home directory \"$dir\" of user \"$user\" does not
exist." else; for file in $dir/.netrc; do if [ ! -h "$file" ] && [ -f "$file" ]; then fileperm="$(ls -ld "$file" | cut -f1 -d" ")"; if [ "$(echo "$fileperm" | cut -c5)" != "-" ]; then echo "Group Read set on \"$file\""; fi; if [ "$(echo "$fileperm" | cut -c6)" != "-" ]; then echo "Group Write set on \"$file\""; fi; if [ "$(echo "$fileperm" | cut -c7)" != "-" ]; then echo "Group Execute set on \"$file\""; fi; if [ "$(echo "$fileperm" | cut -c8)" != "-" ]; then echo "Other Read set on \"$file\""; fi; if [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then echo "Other Write set on \"$file\""; fi; if [ "$(echo "$fileperm" | cut -c10)" != "-" ]; then echo "Other Execute set on \"$file\""; fi; fi; done; fi; done`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring no users have .rhosts files

OUTPUT=`grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do if [ ! -d "$dir" ]; then echo "The home directory \"$dir\" of user \"$user\" does not
exist." else; for file in $dir/.rhosts; do if [ ! -h "$file" ] && [ -f "$file" ]; then echo ".rhosts file in \"$dir\""; fi; done; fi; done`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo "$OUTPUT"
fi

##############################################################################################################

# Ensuring all groups in /etc/passwd exist in /etc/group
OUTPUT=`awk -F: '{print $4}' /etc/passwd | while read -r gid; do if ! grep -E -q "^.*?:[^:]*:$gid:" /etc/group; then echo "The group ID \"$gid\" does not exist in /etc/group"; fi; done`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo $OUTPUT
fi

##############################################################################################################

# Ensuring no duplicate UIDs exist
OUTPUT=`awk -F: '{print $3}' /etc/passwd | sort -n | uniq -c | while read -r uid; do [ -z "$uid" ] && break; set - $uid; if [ $1 -gt 1 ]; then users=$(awk -F: '($3 == n) { print $1 }' n="$2" /etc/passwd | xargs); echo "Duplicate UID \"$2\": \"$users\""; fi; done`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo $OUTPUT
fi

##############################################################################################################

# Ensuring no duplicate GIDs exist
OUTPUT=`cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do echo "Duplicate GID ($x) in /etc/group"; done;`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo $OUTPUT
fi

##############################################################################################################

# Ensuring no duplicate user names exist
OUTPUT=`cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r usr; do echo "Duplicate login name \"$usr\" in /etc/passwd"; done;`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo $OUTPUT
fi

##############################################################################################################

# Ensuring no duplicate group names exist
OUTPUT=`cut -d: -f1 /etc/group | sort | uniq -d | while read -r grp; do echo "Duplicate group name \"$grp\" exists in /etc/group"; done;`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo $OUTPUT
fi

##############################################################################################################

# Ensuring shadow group is empty
OUTPUT=`grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo $OUTPUT
fi

##############################################################################################################

OUTPUT=`awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd`

if [[ $? -eq 0 ]]; then
    echo "OK"
else
    echo $OUTPUT
fi
