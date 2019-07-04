#!/bin/bash

if [ $USER != 'root' ]; then
	echo "ขออภัยสำหรับการเรียกใช้สคริปท์โปรดใช้ผู้ใช้ root"
	exit
fi

# CHECK OS
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [[ $ether = "" ]]; then
        ether=eth0
fi

myip=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
if [ "$MYIP" = "" ]; then
	myip=$(wget -qO- ipv4.icanhazip.com)
fi
MYIP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
if [ "$MYIP" = "" ]; then
	MYIP=$(wget -qO- ipv4.icanhazip.com)
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [[ $ether = "" ]]; then
        ether=eth0
	fi
cd
clear
 echo ""
          echo -e "\e[031;1m     
          
                =============== OS-32 & 64-bit ================
                
                    >>>>> โปรดชำระเงินก่อนใช้สคริปท์อัตโนมัติ <<<<<
                  ..........................................
                  .        สคริปท์นี้ราคา 150 บาท                .
                  .        ***********************         .
                  .        True Wallet Account             .
                  .        =======================         .
                  .        Phone : 094-927-5858            .
                  .        Name  : พีรพล เมืองจันทร์           .
                  ..........................................   
                                      
                           [ขอบคุณสำหรับการใช้งานสคริปท์]
                              [สคริปท์สำหรับผู้ใช้VIP เท่านั้น]
                                   
                               ( ใส่รหัสผ่านติดตั้ง )"
			
	echo ""
    read -p "โปรดใส่รหัสสำหรับติดตั้ง:" passwds
wget -q -O /usr/bin/pass www.noi-vpn.tk/www.noi-vpn.tk.txt
if ! grep -w -q $passwds /usr/bin/pass; then
clear
echo ""
echo ""
echo " เสียใจด้วย รหัสผิด ถ้าไม่มีรหัสติดต่อแอดมินฯ"
echo ""
echo " FB : https://www.facebook.com/Amkoonp"
echo ""
echo ""
rm /usr/bin/pass
rm Install.sh
exit

fi

# Disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# Install wget and curl
apt-get update;apt-get -y install wget curl;

# Set Location GMT +7
ln -fs /usr/share/zoneinfo/Asia/Thailand /etc/localtime

# Set Locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# Set repo
cat > /etc/apt/sources.list <<END
deb http://cdn.debian.net/debian wheezy main contrib non-free
deb http://security.debian.org/ wheezy/updates main contrib non-free
deb http://packages.dotdeb.org wheezy all
deb http://download.webmin.com/download/repository sarge contrib
deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib
END
wget "http://www.noi-vpn.tk/script/Config/dotdeb.gpg"
wget "http://www.noi-vpn.tk/script/Config/jcameron-key.asc"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# Update
apt-get update

# Install Webserver
apt-get -y install nginx

# Install Essential Package
apt-get -y install nano iptables dnsutils openvpn screen whois ngrep unzip unrar

# Install Screenfetch
cd
wget -O /usr/bin/screenfetch "http://www.noi-vpn.tk/script/Config/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

# Install Webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
cat > /etc/nginx/nginx.conf <<END3
user www-data;
worker_processes 1;
pid /var/run/nginx.pid;
events {
	multi_accept on;
  worker_connections 1024;
}
http {
	gzip on;
	gzip_vary on;
	gzip_comp_level 5;
	gzip_types    text/plain application/x-javascript text/xml text/css;
	autoindex on;
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;
  server_tokens off;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log;
  client_max_body_size 32M;
	client_header_buffer_size 8m;
	large_client_header_buffers 8 8m;
	fastcgi_buffer_size 8m;
	fastcgi_buffers 8 8m;
	fastcgi_read_timeout 600;
  include /etc/nginx/conf.d/*.conf;
}
END3
mkdir -p /home/vps/public_html
echo "<pre>Source by www.noi-vpn.tk | Donate at TrueMoney Wallet 094-927-5858</pre>" > /home/vps/public_html/index.html
echo "<?phpinfo(); ?>" > /home/vps/public_html/info.php
args='$args'
uri='$uri'
document_root='$document_root'
fastcgi_script_name='$fastcgi_script_name'
cat > /etc/nginx/conf.d/vps.conf <<END4
server {
  listen       85;
  server_name  127.0.0.1 localhost;
  access_log /var/log/nginx/vps-access.log;
  error_log /var/log/nginx/vps-error.log error;
  root   /home/vps/public_html;
  location / {
    index  index.html index.htm index.php;
    try_files $uri $uri/ /index.php?$args;
  }
  location ~ \.php$ {
    include /etc/nginx/fastcgi_params;
    fastcgi_pass  127.0.0.1:9000;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
}
END4
/etc/init.d/nginx restart

# install vnstat gui
cd /home/vps/public_html/
wget https://raw.githubusercontent.com/daybreakersx/premscript/master/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i "s/\$iface_list = array('eth0', 'sixxs');/\$iface_list = array('eth0');/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
cd

# install fail2ban
apt-get -y install fail2ban
service fail2ban restart

# Install OpenVPN
wget -O /etc/openvpn/openvpn.tar "http://www.noi-vpn.tk/script/Config/openvpn.tar"
cd /etc/openvpn/
tar xf openvpn.tar
cat > /etc/openvpn/1194.conf <<END
port 1194
proto tcp
dev tun

ca /etc/openvpn/keys/ca.crt
dh /etc/openvpn/keys/dh1024.pem
cert /etc/openvpn/keys/server.crt
key /etc/openvpn/keys/server.key

plugin /usr/lib/openvpn/openvpn-auth-pam.so /etc/pam.d/login
client-cert-not-required
username-as-common-name

server 192.168.100.0  255.255.255.0
push "redirect-gateway def1"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

cipher none
comp-lzo

keepalive 5 30

persist-key
persist-tun
client-to-client
status log.log
verb 3
mute 10
END
service openvpn restart
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
iptables -t nat -I POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
iptables-save > /etc/iptables_new.conf
cat > /etc/network/if-up.d/iptables <<END
#!/bin/sh
iptables-restore < /etc/iptables_new.conf
END
chmod +x /etc/network/if-up.d/iptables
service openvpn restart

# Setting Port SSH
cd
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 443' /etc/ssh/sshd_config
service ssh restart

# Install Dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 443 -p 80"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/ssh restart
/etc/init.d/dropbear restart

# install squid3
apt-get -y install squid3
cat > /etc/squid3/squid.conf <<-END
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxx-xxxxxxxxx/32
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
http_port 8000
http_port 80
http_port 3128
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname daybreakersx
END
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

#installing webmin
wget http://www.webmin.com/jcameron-key.asc
apt-key add jcameron-key.asc
echo "deb http://download.webmin.com/download/repository sarge contrib" >> /etc/apt/sources.list
echo "deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib" >> /etc/apt/sources.list
apt-get update
apt-get -y install webmin

#disable webmin https
sed -i "s/ssl=1/ssl=0/g" /etc/webmin/miniserv.conf
/etc/init.d/webmin restart
service vnstat restart

#Setting IPtables
cat > /etc/iptables.up.rules <<-END
*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -j SNAT --to-source xxxxxxxxx
-A POSTROUTING -o eth0 -j MASQUERADE
-A POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
-A POSTROUTING -s 10.1.0.0/24 -o eth0 -j MASQUERADE
COMMIT

*filter
:INPUT ACCEPT [19406:27313311]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [9393:434129]
:fail2ban-ssh - [0:0]
-A FORWARD -i eth0 -o ppp0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i ppp0 -o eth0 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 22 -j fail2ban-ssh
-A INPUT -p ICMP --icmp-type 8 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -p tcp --dport 22  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 85  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 142  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 143  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 109  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 110  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 443  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 1194  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 1194  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 1732  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 1732  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 7300  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 7300  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8000  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8000  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8080  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8080  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 10000  -m state --state NEW -j ACCEPT
-A fail2ban-ssh -j RETURN
COMMIT

*raw
:PREROUTING ACCEPT [158575:227800758]
:OUTPUT ACCEPT [46145:2312668]
COMMIT

*mangle
:PREROUTING ACCEPT [158575:227800758]
:INPUT ACCEPT [158575:227800758]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [46145:2312668]
:POSTROUTING ACCEPT [46145:2312668]
COMMIT
END
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
sed -i $MYIP2 /etc/iptables.up.rules;
iptables-restore < /etc/iptables.up.rules

# Install Script
cd /usr/local/bin
wget http://www.noi-vpn.tk/script/Config/menu
wget http://www.noi-vpn.tk/script/Config/speedtest
chmod +x menu
chmod +x speedtest
echo ""
echo "..... Installing 98% ...restarting service."

# Finishing
apt-get -y autoremove
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/nginx restart
service openvpn restart
service cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
service vnstat restart
service squid3 restart
service webmin restart
sysv-rc-conf rc.local on

#clearing history
history -c

# info
clear
echo "====================================================="
echo ""
echo " - OpenVPN  : TCP Port 1194"
echo " - OpenSSH  : Port 22, 143"
echo " - Dropbear : Port 80, 443"
echo " - Squid3   : Port 8080"
echo ""
echo "====================================================="
echo "ติดตั้งสคริปท์สำเร็จแล้ว ให้ใช้คำสั่ง menu เพื่อเข้าเมนูใช้งานสคริปท์นี้"
echo "====================================================="
echo "《Script by NoiVPN》"
cd
rm -f /root/Install.sh
