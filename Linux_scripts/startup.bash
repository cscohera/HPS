#!/bin/bash
#Thrown together by Ardian Peach (oatzs) for the Fall 2023 KnightHacksHorse Plinko Cyber Challenge at the University of Central Florida
passwd -l root

echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "Protocol 2" >> /etc/ssh/sshd_config
#SSH whitelist
echo "AllowUsers hkeating ubuntu" >> /etc/ssh/sshd_confi

apt install ufw -y
#metasploit default port
ufw deny 4444

#sets firewall rules
ufw allow 'Apache Secure' #443
ufw allow OpenSSH
ufw allow ftp
ufw allow http
ufw allow 20 tcp
ufw allow 990 tcp
ufw enable


sudo chown -R root:root /etc/apache2

#removing nopasswdlogon group
echo "Removing nopasswdlogon group"
sed -i -e '/nopasswdlogin/d' /etc/group

chmod 644 /etc/passwd

#Backup file required for scoring
cp /files/Seabiscuit.jpg ~
cp /files/Seabiscuit.jpg /bin
cp /files/Seabiscuit.jpg /media
cp /files/Seabiscuit.jpg /var
chattr +i /files/Seabiscuit.jpg

#allow only the scoring user
echo "hkeating" >> /etc/vsftpd.userlist
echo "userlist_enable=YES" >> /etc/vsftpd.userlist
echo "userlist_file=/etc/vsftpd.userlist" >> /etc/vsftpd.conf
echo "userlist_deny=NO" >> /etc/vsftpd.conf
echo "chroot_local_user=NO" >> /etc/vsftpd.conf

#general
echo "anonymous_enable=NO" >> /etc/vsftpd.conf
echo "local_enable=YES" >> /etc/vsftpd.conf
echo "write_enable=YES" >> /etc/vsftpd.conf
echo "xferlog_enable=YES" >> /etc/vsftpd.conf
echo "ascii_upload_enable=NO" >> /etc/vsftpd.conf
echo "ascii_download_enable=NO" >> /etc/vsftpd.conf
service vsftpd restart


#updates the repo so we can download our very useful tools
apt update -y
apt install ranger -y
apt install fail2ban -y
apt install tmux -y
apt install curl -y
apt install whowatch -y

wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64

for user in $( sed 's/:.*//' /etc/passwd);
	do
	  if [[ $( id -u $user) -ge 999 && "$user" != "nobody" ]]
	  then
		(echo "PASSWORD!"; echo "PASSWORD!") |  passwd "$user"
	  fi
done

pwck

chattr +i /etc/vsftpd.userlist
chattr +i /etc/vsftpd.conf
chattr +i /etc/ssh/sshd_config