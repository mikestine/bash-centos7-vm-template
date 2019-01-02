#!/bin/bash
#
# Syspreps and Configs centos7 image for VM Cloning
# This script is idempotent


set -o pipefail

# This might cause problems e.g. using read to read a heredoc cause
# read to always return non-zero set -o errexit Treat unset variables
# as an error when substituting.
set -o nounset
set -o errexit

# set -o noexec ## Commands are not executed, only syntax check
# set -o verbose ## Outputs the lines of a script before execution
# set -o xtrace ## Outputs the lines of a script after replacements


# SET GLOBAL CONSTANTS
# a reliable way for a bash script to get the full path to itself
declare -r SCRIPTPATH=$( cd $(dirname ${BASH_SOURCE[0]}) > /dev/null; pwd -P ) 


# FONTS
NORM=`tput sgr0`
BOLD=`tput bold`
REV=`tput smso`


# all progs need to be given as parameters
# e.g. _check_required_programs md5 xsltproc
function _check_required_programs() {
    # Required program(s)
    for p in ${@}; do
    hash "${p}" 2>&- || \
        { echo >&2 "Required program \"${p}\" not installed or in search PATH.";
              exit 1;
            }
    done
}




function isInstalled {
  if yum list installed "$@" >/dev/null 2>&1; then
    true
  else
    false
  fi
}



#######################################
# Upgrades yum package(s), or install if not installed
# Arguments:
#   $@ (optional): Package name or names
# usage:
#   prepc7::install_latest nmap vim ntp
#######################################
function prepc7::install_latest {
    
    #if no parameters, upgrade everything
    if [[ $# -eq 0 ]] ; then
        echo "Update kernel/OS/packages to highest minor releases"
        yum -y update 

        echo "Upgrading kernel/OS/packages to highest major release"
        yum -y upgrade
    fi
    #loop through params and install and update and upgrade yum packages
    for package in "$@"; do
        if ! yum list installed "$package" >/dev/null 2>&1;  then 
            echo "installing $package"
            yum -y install "$package"
        else 
            echo "$package already installed"   
        fi
        
        yum -y update "$package"
        yum -y upgrade "$package"
        
    done    
}

# prepc7 Function Package
 
 

 


function die() {
  echo "${0##*/}: error: $*" >&2
  exit 1
}

function cleanup() {
    echo "Cleaned up...  Good Bye!" && exit 100   
}
 
# function usage () {
    # # No tabs necessary!
    # closing="That's all"
    # readarray message <<EOF
       # : Hello, this is a cool program.
       # : This should get unindented.
       # : This code should stay indented:
       # :      something() {
       # :          echo It works, yo!;
       # :      }
       # : $closing
# EOF
    # shopt -s extglob
    # printf '%s' "${message[@]#+( ): }"
    # shopt -u extglob
    
    # exit 0
# }
function usage() {
  echo "Usage: prepc7 [options] [args]

This does something useful!

Options:
  -o <file>   Write output to <file>
  -v          Run verbosely
  -h          This help screen"
}

function prepc7::hostname() {
  local addr
  addr="${1:-}"
  
  echo "Removing Hostname FROM: /etc/sysconfig/network"
  sed -i -r "/^HOSTNAME=\S*$/d" /etc/sysconfig/network
  cat /etc/sysconfig/network
  
  echo "Setting Hostname TO: $addr"
  hostnamectl set-hostname "$addr"
  hostnamectl
}




function prepc7::config() {

  ###########################################################################
  echo "Stop Firewalld"
	systemctl stop firewalld
  echo "Disable Firewalld"
	systemctl disable firewalld
  
  ###########################################################################
  echo "Stop Iptables Service"
  systemctl stop iptables
  echo "Disable Iptables Service"
  systemctl disable iptables  
  
  ###########################################################################
  echo "Disable SELinux"
	setenforce 0
	sed -i -r 's/^#?(SELINUX=)(enforcing|permissive|disabled)/\1disabled/' /etc/selinux/config
  sestatus
  
  ###########################################################################
  echo "enable NTP"
  prepc7::install_latest ntp
  timedatectl set-timezone America/Los_Angeles
  
  #replace first instance with placeholder
  sed -i -r "0,/^server \S+ iburst$/s//--prepc7-ntp-placeholder--/" "/etc/ntp.conf"
  #remove all instances
  sed -i -r "s/^server \S+ iburst$//" "/etc/ntp.conf"
  #replace placeholder
  sed -i -r "s/^--prepc7-ntp-placeholder--$/server cbs.ntp.com iburst/" "/etc/ntp.conf"
  
  systemctl enable ntpd
  systemctl restart ntpd 
  ntpstat
  
  ###########################################################################  
  echo "Install Yum Utils"
  prepc7::install_latest yum-utils
  prepc7::install_latest yum-plugin-remove-with-leaves
  
  echo "Install VM essentials"
	prepc7::install_latest open-vm-tools

	echo "After installing VM tools restart the service"
	systemctl restart vmtoolsd
  

  echo "Install System Utils"
	prepc7::install_latest vim-enhanced
  
  echo "Install System Utils"
	#prepc7::install_latestl net-tools # (deprecated in Cent7) Network Tools ie ifconfig, netstat, route
	prepc7::install_latest links
	prepc7::install_latest nmap
	prepc7::install_latest wget
	prepc7::install_latest telnet
	prepc7::install_latest unzip
	prepc7::install_latest bzip2
	prepc7::install_latest nano
	prepc7::install_latest rsync
  

  
  echo "Install SysAdmin Tools"
	prepc7::install_latest bind-utils bind-libs #used for domain name resolution
	prepc7::install_latest ntsysv
	prepc7::install_latest pciutils
	prepc7::install_latest pinfo
	prepc7::install_latest pm-utils
	prepc7::install_latest psacct
	prepc7::install_latest quota
	prepc7::install_latest rdate
	prepc7::install_latest rng-tools
	prepc7::install_latest satyr
	prepc7::install_latest setserial
	prepc7::install_latest smartmontools
	prepc7::install_latest strace
	prepc7::install_latest sysstat
	prepc7::install_latest lsof
	prepc7::install_latest psmisc
	prepc7::install_latest iotop
	prepc7::install_latest lshw
	prepc7::install_latest mtr
	prepc7::install_latest dstat
	prepc7::install_latest socat
	prepc7::install_latest iperf3
 
  
  echo "install development tools"
	# autoconf, automake, binutils, bison, flex, gcc, gcc-c++, gettext, libtool, 
  # make, patch, pkgconfig, redhat-rpm-config, rpm-build, rpm-sign
	prepc7::install_latest groupinstall development
	
	echo "install languages"
	prepc7::install_latest gcc make perl python kernel-headers kernel-devel
  
  echo "install 3rd party"
	prepc7::install_latest epel-release
	prepc7::install_latest p7zip
	prepc7::install_latest ntfs-3g
	prepc7::install_latest hping3
	prepc7::install_latest nethogs
  prepc7::install_latest htop
	prepc7::install_latest bash-completion bash-completion-extras
}

function prepc7::sysprep() {
    echo "*prepc7::sysprep*"
    
    prepc7::hostname "localhost.localdomain"
    
    echo "yum remove dependencies which are no longer used because of a removal"
    yum autoremove

    echo "clean yum cache"
    yum clean all

    echo "free space taken by orphaned data from disabled or removed yum repos"
    rm -rf /var/cache/yum

    echo "remove old kernels"
    /bin/package-cleanup -y --oldkernels –-count=1

    echo "stop logging services"
    systemctl stop rsyslog.service
    service auditd stop

    echo "Force the logs to rotate & remove old logs we don’t need"
    /usr/sbin/logrotate /etc/logrotate.conf --force
    rm -f /var/log/*-???????? /var/log/*.gz
    rm -f /var/log/dmesg.old
    rm -rf /var/log/anaconda

    echo "Truncate audit logs (and other logs we want to keep placeholders for)"
    cat /dev/null > /var/log/audit/audit.log
    cat /dev/null > /var/log/wtmp
    cat /dev/null > /var/log/lastlog
    cat /dev/null > /var/log/grubby

    echo "remove udev hardware rules"
    rm -f /etc/udev/rules.d/70*

    echo "Remove the traces of the template MAC address and UUIDs"
    sed -i '/^\(HWADDR\|UUID\)=/d' /etc/sysconfig/network-scripts/ifcfg-e*

    echo "enable network interface onboot"
    sed -i -e 's/^ONBOOT="no/ONBOOT="yes/' /etc/sysconfig/network-scripts/ifcfg-e*

    echo "Clean /tmp out"
    rm -rf /tmp/*
    rm -rf /var/tmp/*

    echo "remove SSH host keys"
    rm -f /etc/ssh/*key*

    echo "Remove the root user’s SSH history"
    rm -rf ~root/.ssh/
    rm -f ~root/anaconda-ks.cfg

    echo "remove the root password"
    passwd -d root

    echo "support guest customization of CentOS 7 in vSphere 5.5 and vCloud Air"
    mv /etc/redhat-release /etc/redhat-release.old
    touch /etc/redhat-release
    echo 'Red Hat Enterprise Linux Server release 7.0 (Maipo)' > /etc/redhat-release

    echo "Remove the root user’s shell history"
    history -cw

    echo "remove root users shell history"
    rm -f ~root/.bash_history
    unset HISTFILE

    # The  sys-unconfig  command  is used to restore a system's configuration to
    # an "as-manufactured" state, ready to be reconfigured again. The system's 
    # configuration consists of host-name, Network Information Service (NIS) 
    # domain name, timezone, IP address, IP subnet mask,and root password
    sys-unconfig
}


 

function main() {

    local opt current_arg argz
    
            # -opt arg1 arg2
        # argz=(arg1,arg2)
    
    if [[ "$1" =~ ^((-{1,2})([Hh]$|[Hh][Ee][Ll][Pp])|)$ ]]; then
      usage; exit 1
    else
      while [[ $# -gt 0 ]]; do              
        opt="$1"        
        shift
        current_arg="${1:-}"
                
        # get following arguments that don't start with dash
        argz=()
        while [[ $# -gt 0 && ! "$current_arg" == -* ]]; do         
          argz+=("$current_arg")
          shift
          current_arg="${1:-}"
        done
        
        #turn on extended globbing
        #shopt -s extglob
        
        case "$opt" in
          "-d"|"--debug") set -o xtrace ;;
          "-o"|"--hostname") prepc7::hostname ${argz[@]+"${argz[@]}"} ;;
          "-t"|"--test") prepc7::testx ${argz[@]+"${argz[@]}"} ;;
          "-c"|"--config") prepc7::config;;
          "-s"|"--sysprep") prepc7::config;;
          "-h"|"--help") prepc7::testx ${argz[@]+"${argz[@]}"} ;;
          *                 ) echo "ERROR: Invalid option: \""$opt"\"" >&2; usage; exit 1;;
        esac
      done
    fi
 
    
  cleanup

  exit 0
}

# Trap signal interrupts, and cleanup before terminating
#  1, SIGHUP,  Hang up detected on controlling terminal or death of controlling process
#  2, SIGINT,  Issued if the user sends an interrupt signal (Ctrl + C)
#  3, SIGQUIT, Issued if the user sends a quit signal (Ctrl + D)
# 13, SIGPIPE, Broken Pipe
# 15, SIGTERM, Software termination signal (sent by kill by default)

trap "cleanup; exit 1" 1 2 3 13 15

# this is the main function that starts the script, all params are passed to main
main "$@"


# TODO: function prepc7::ntp { }
# brace all non positional special params.
# add user
# remove root 22 support
