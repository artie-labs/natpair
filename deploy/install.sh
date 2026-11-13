#!/bin/sh
# Installs natpair on a dedicated Amazon Linux 2023 NAT image. Enables the
# services for the next boot but does not start them. Do not run on a serving
# NAT. First boot runs it, and so does the updater, only on a NAT that doesn't
# serve, before rebooting into the new release.
#
# Usage: install.sh <path to the natpair binary for this architecture>
set -eu
test "$(id -u)" = 0
binary=$1
deploy_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

test -f /etc/natpair/config.json
dnf install -y conntrack-tools iptables-nft
install -m 0755 "$binary" /usr/local/bin/natpair
/usr/local/bin/natpair validate --config /etc/natpair/config.json
chmod 0600 /etc/natpair/config.json

install -d -m 0700 /var/lib/natpair
install -d -m 0755 /etc/systemd/system/conntrackd.service.d /etc/systemd/networkd.conf.d
install -m 0644 "$deploy_dir/natpair-bootstrap.service" "$deploy_dir/natpair.service" "$deploy_dir/natpair.slice" /etc/systemd/system/
install -m 0644 "$deploy_dir/conntrackd-override.conf" /etc/systemd/system/conntrackd.service.d/natpair.conf
install -m 0644 "$deploy_dir/90-natpair.conf" /etc/sysctl.d/
install -m 0644 "$deploy_dir/networkd-natpair.conf" /etc/systemd/networkd.conf.d/natpair.conf
systemctl daemon-reload
systemctl enable natpair-bootstrap.service natpair.service conntrackd.service
# Open shells with Session Manager, not SSH. The security group must
# leave port 22 open to the Internet, and the host firewall only closes it once
# the bootstrap service runs, so sshd is turned off.
systemctl disable --now sshd.service
echo "Installed for the next boot. No services were started."
