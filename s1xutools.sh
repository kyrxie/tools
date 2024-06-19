#!/bin/bash

sh_v="1.0.2"

huang='\033[33m'
bai='\033[0m'
lv='\033[0;32m'
lan='\033[0;34m'
hong='\033[31m'
s1xu='\033[96m'
hui='\e[37m'

cp ./s1xutools.sh /usr/local/bin/xx >/dev/null 2>&1

ip_address() {
	ipv4_address=$(curl -s ipv4.ip.sb)
	ipv6_address=$(curl -s --max-time 1 ipv6.ip.sb)
}

install() {
	if [ $# -eq 0 ]; then
		echo "未提供软件包参数!"
		return 1
	fi

	for package in "$@"; do
		if ! command -v "$package" &>/dev/null; then
			if command -v dnf &>/dev/null; then
				dnf -y update && dnf install -y "$package"
			elif command -v yum &>/dev/null; then
				yum -y update && yum -y install "$package"
			elif command -v apt &>/dev/null; then
				apt update -y && apt install -y "$package"
			elif command -v apk &>/dev/null; then
				apk update && apk add "$package"
			else
				echo "未知的包管理器!"
				return 1
			fi
		fi
	done

	return 0
}

install_dependency() {
	clear
	install wget socat unzip tar
}

remove() {
	if [ $# -eq 0 ]; then
		echo "未提供软件包参数!"
		return 1
	fi

	for package in "$@"; do
		if command -v dnf &>/dev/null; then
			dnf remove -y "${package}*"
		elif command -v yum &>/dev/null; then
			yum remove -y "${package}*"
		elif command -v apt &>/dev/null; then
			apt purge -y "${package}*"
		elif command -v apk &>/dev/null; then
			apk del "${package}*"
		else
			echo "未知的包管理器!"
			return 1
		fi
	done

	return 0
}

break_end() {
	echo -e "${lv}操作完成${bai}"
	echo "按任意键继续..."
	read -n 1 -s -r -p ""
	echo ""
	clear
}

s1xu() {
	xx
	exit
}

check_port() {
	# 定义要检测的端口
	PORT=443

	# 检查端口占用情况
	result=$(ss -tulpn | grep ":$PORT")

	# 判断结果并输出相应信息
	if [ -n "$result" ]; then
		is_nginx_container=$(docker ps --format '{{.Names}}' | grep 'nginx')

		# 判断是否是Nginx容器占用端口
		if [ -n "$is_nginx_container" ]; then
			echo ""
		else
			clear
			echo -e "${hong}端口 ${huang}$PORT${hong} 已被占用，无法安装环境，卸载以下程序后重试！${bai}"
			echo "$result"
			break_end
			s1xu

		fi
	else
		echo ""
	fi
}

install_add_docker() {
	if [ -f "/etc/alpine-release" ]; then
		apk update
		apk add docker docker-compose
		rc-update add docker default
		service docker start
	else
		country=$(curl -s ipinfo.io/country)
		if [ "$country" = "CN" ]; then
			cd ~
			curl -sS -O https://raw.gitmirror.com/kejilion/docker/main/install && chmod +x install
			sh install --mirror Aliyun
			rm -f install
			cat >/etc/docker/daemon.json <<EOF
{
    "registry-mirrors": ["https://docker.888166.xyz"]
}
EOF
		else
			curl -fsSL https://get.docker.com | sh
		fi
		systemctl start docker
		systemctl enable docker
	fi

	sleep 2
}

install_docker() {
	if ! command -v docker &>/dev/null; then
		install_add_docker
	else
		echo "Docker环境已经安装"
	fi
}

docker_restart() {
	if [ -f "/etc/alpine-release" ]; then
		service docker restart
	else
		systemctl restart docker
	fi

}

docker_ipv6_on() {
	mkdir -p /etc/docker &>/dev/null

	cat >/etc/docker/daemon.json <<EOF

{
  "ipv6": true,
  "fixed-cidr-v6": "2001:db8:1::/64"
}

EOF

	docker_restart

	echo "Docker已开启v6访问"

}

docker_ipv6_off() {

	rm -rf etc/docker/daemon.json &>/dev/null

	docker_restart

	echo "Docker已关闭v6访问"

}

iptables_open() {
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -F

	ip6tables -P INPUT ACCEPT
	ip6tables -P FORWARD ACCEPT
	ip6tables -P OUTPUT ACCEPT
	ip6tables -F

}

add_swap() {
	# 获取当前系统中所有的 swap 分区
	swap_partitions=$(grep -E '^/dev/' /proc/swaps | awk '{print $1}')

	# 遍历并删除所有的 swap 分区
	for partition in $swap_partitions; do
		swapoff "$partition"
		wipefs -a "$partition" # 清除文件系统标识符
		mkswap -f "$partition"
	done

	# 确保 /swapfile 不再被使用
	swapoff /swapfile

	# 删除旧的 /swapfile
	rm -f /swapfile

	# 创建新的 swap 分区
	dd if=/dev/zero of=/swapfile bs=1M count=$new_swap
	chmod 600 /swapfile
	mkswap /swapfile
	swapon /swapfile

	if [ -f /etc/alpine-release ]; then
		echo "/swapfile swap swap defaults 0 0" >>/etc/fstab
		echo "nohup swapon /swapfile" >>/etc/local.d/swap.start
		chmod +x /etc/local.d/swap.start
		rc-update add local
	else
		echo "/swapfile swap swap defaults 0 0" >>/etc/fstab
	fi

	echo -e "虚拟内存大小已调整为${huang}${new_swap}${bai}MB"
}

ldnmp_v() {

	# 获取nginx版本
	nginx_version=$(docker exec nginx nginx -v 2>&1)
	nginx_version=$(echo "$nginx_version" | grep -oP "nginx/\K[0-9]+\.[0-9]+\.[0-9]+")
	echo -n -e "nginx : ${huang}v$nginx_version${bai}"

	# 获取mysql版本
	dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	mysql_version=$(docker exec mysql mysql -u root -p"$dbrootpasswd" -e "SELECT VERSION();" 2>/dev/null | tail -n 1)
	echo -n -e "            mysql : ${huang}v$mysql_version${bai}"

	# 获取php版本
	php_version=$(docker exec php php -v 2>/dev/null | grep -oP "PHP \K[0-9]+\.[0-9]+\.[0-9]+")
	echo -n -e "            php : ${huang}v$php_version${bai}"

	# 获取redis版本
	redis_version=$(docker exec redis redis-server -v 2>&1 | grep -oP "v=+\K[0-9]+\.[0-9]+")
	echo -e "            redis : ${huang}v$redis_version${bai}"

	echo "------------------------"
	echo ""

}

install_ldnmp() {

	new_swap=1024
	add_swap

	cd /home/web && docker compose up -d
	clear
	echo "正在配置LDNMP环境，请耐心稍等……"

	# 定义要执行的命令
	commands=(
		"docker exec nginx chmod -R 777 /var/www/html"
		"docker restart nginx > /dev/null 2>&1"

		# "docker exec php sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories > /dev/null 2>&1"
		# "docker exec php74 sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories > /dev/null 2>&1"

		"docker exec php apk update > /dev/null 2>&1"
		"docker exec php74 apk update > /dev/null 2>&1"

		# php安装包管理
		"curl -sL https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions -o /usr/local/bin/install-php-extensions > /dev/null 2>&1"
		"docker exec php mkdir -p /usr/local/bin/ > /dev/null 2>&1"
		"docker exec php74 mkdir -p /usr/local/bin/ > /dev/null 2>&1"
		"docker cp /usr/local/bin/install-php-extensions php:/usr/local/bin/ > /dev/null 2>&1"
		"docker cp /usr/local/bin/install-php-extensions php74:/usr/local/bin/ > /dev/null 2>&1"
		"docker exec php chmod +x /usr/local/bin/install-php-extensions > /dev/null 2>&1"
		"docker exec php74 chmod +x /usr/local/bin/install-php-extensions > /dev/null 2>&1"

		# php安装扩展
		"docker exec php install-php-extensions mysqli > /dev/null 2>&1"
		"docker exec php install-php-extensions pdo_mysql > /dev/null 2>&1"
		"docker exec php install-php-extensions gd > /dev/null 2>&1"
		"docker exec php install-php-extensions intl > /dev/null 2>&1"
		"docker exec php install-php-extensions zip > /dev/null 2>&1"
		"docker exec php install-php-extensions exif > /dev/null 2>&1"
		"docker exec php install-php-extensions bcmath > /dev/null 2>&1"
		"docker exec php install-php-extensions opcache > /dev/null 2>&1"
		"docker exec php install-php-extensions imagick > /dev/null 2>&1"
		"docker exec php install-php-extensions redis > /dev/null 2>&1"

		# php配置参数
		"docker exec php sh -c 'echo \"upload_max_filesize=50M \" > /usr/local/etc/php/conf.d/uploads.ini' > /dev/null 2>&1"
		"docker exec php sh -c 'echo \"post_max_size=50M \" > /usr/local/etc/php/conf.d/post.ini' > /dev/null 2>&1"
		"docker exec php sh -c 'echo \"memory_limit=256M\" > /usr/local/etc/php/conf.d/memory.ini' > /dev/null 2>&1"
		"docker exec php sh -c 'echo \"max_execution_time=1200\" > /usr/local/etc/php/conf.d/max_execution_time.ini' > /dev/null 2>&1"
		"docker exec php sh -c 'echo \"max_input_time=600\" > /usr/local/etc/php/conf.d/max_input_time.ini' > /dev/null 2>&1"

		# php重启
		"docker exec php chmod -R 777 /var/www/html"
		"docker restart php > /dev/null 2>&1"

		# php7.4安装扩展
		"docker exec php74 install-php-extensions mysqli > /dev/null 2>&1"
		"docker exec php74 install-php-extensions pdo_mysql > /dev/null 2>&1"
		"docker exec php74 install-php-extensions gd > /dev/null 2>&1"
		"docker exec php74 install-php-extensions intl > /dev/null 2>&1"
		"docker exec php74 install-php-extensions zip > /dev/null 2>&1"
		"docker exec php74 install-php-extensions exif > /dev/null 2>&1"
		"docker exec php74 install-php-extensions bcmath > /dev/null 2>&1"
		"docker exec php74 install-php-extensions opcache > /dev/null 2>&1"
		"docker exec php74 install-php-extensions imagick > /dev/null 2>&1"
		"docker exec php74 install-php-extensions redis > /dev/null 2>&1"

		# php7.4配置参数
		"docker exec php74 sh -c 'echo \"upload_max_filesize=50M \" > /usr/local/etc/php/conf.d/uploads.ini' > /dev/null 2>&1"
		"docker exec php74 sh -c 'echo \"post_max_size=50M \" > /usr/local/etc/php/conf.d/post.ini' > /dev/null 2>&1"
		"docker exec php74 sh -c 'echo \"memory_limit=256M\" > /usr/local/etc/php/conf.d/memory.ini' > /dev/null 2>&1"
		"docker exec php74 sh -c 'echo \"max_execution_time=1200\" > /usr/local/etc/php/conf.d/max_execution_time.ini' > /dev/null 2>&1"
		"docker exec php74 sh -c 'echo \"max_input_time=600\" > /usr/local/etc/php/conf.d/max_input_time.ini' > /dev/null 2>&1"

		# php7.4重启
		"docker exec php74 chmod -R 777 /var/www/html"
		"docker restart php74 > /dev/null 2>&1"
	)

	total_commands=${#commands[@]} # 计算总命令数

	for ((i = 0; i < total_commands; i++)); do
		command="${commands[i]}"
		eval $command # 执行命令

		# 打印百分比和进度条
		percentage=$(((i + 1) * 100 / total_commands))
		completed=$((percentage / 2))
		remaining=$((50 - completed))
		progressBar="["
		for ((j = 0; j < completed; j++)); do
			progressBar+="#"
		done
		for ((j = 0; j < remaining; j++)); do
			progressBar+="."
		done
		progressBar+="]"
		echo -ne "\r[${lv}$percentage%${bai}] $progressBar"
	done

	echo # 打印换行，以便输出不被覆盖

	clear
	echo "LDNMP环境安装完毕"
	echo "------------------------"
	ldnmp_v

}

install_certbot() {

	if command -v yum &>/dev/null; then
		install epel-release certbot
	else
		install certbot
	fi

	# 切换到一个一致的目录（例如，家目录）
	cd ~ || exit

	# 下载并使脚本可执行
	curl -O https://raw.githubusercontent.com/kyrxie/tools/main/certbot/auto_cert_renewal.sh
	chmod +x auto_cert_renewal.sh

	# 设置定时任务字符串
	cron_job="0 0 * * * ~/auto_cert_renewal.sh"

	# 检查是否存在相同的定时任务
	existing_cron=$(crontab -l 2>/dev/null | grep -F "$cron_job")

	# 如果不存在，则添加定时任务
	if [ -z "$existing_cron" ]; then
		(
			crontab -l 2>/dev/null
			echo "$cron_job"
		) | crontab -
		echo "续签任务已添加"
	else
		echo "续签任务已存在，无需添加"
	fi
}

install_ssltls() {
	docker stop nginx >/dev/null 2>&1
	iptables_open
	cd ~

	certbot_version=$(certbot --version 2>&1 | grep -oP "\d+\.\d+\.\d+")

	version_ge() {
		[ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" != "$1" ]
	}

	if version_ge "$certbot_version" "1.10.0"; then
		certbot certonly --standalone -d $yuming --email your@email.com --agree-tos --no-eff-email --force-renewal --key-type ecdsa
	else
		certbot certonly --standalone -d $yuming --email your@email.com --agree-tos --no-eff-email --force-renewal
	fi

	cp /etc/letsencrypt/live/$yuming/fullchain.pem /home/web/certs/${yuming}_cert.pem
	cp /etc/letsencrypt/live/$yuming/privkey.pem /home/web/certs/${yuming}_key.pem
	docker start nginx >/dev/null 2>&1
}

default_server_ssl() {
	install openssl
	# openssl req -x509 -nodes -newkey rsa:2048 -keyout /home/web/certs/default_server.key -out /home/web/certs/default_server.crt -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"
	if command -v dnf &>/dev/null || command -v yum &>/dev/null; then
		openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout /home/web/certs/default_server.key -out /home/web/certs/default_server.crt -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"
	else
		openssl genpkey -algorithm Ed25519 -out /home/web/certs/default_server.key
		openssl req -x509 -key /home/web/certs/default_server.key -out /home/web/certs/default_server.crt -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"
	fi
}

nginx_status() {
	sleep 1
	nginx_container_name="nginx"
	container_status=$(docker inspect -f '{{.State.Status}}' "$nginx_container_name" 2>/dev/null)
	container_restart_count=$(docker inspect -f '{{.RestartCount}}' "$nginx_container_name" 2>/dev/null)

	if [ "$container_status" == "running" ]; then
		echo ""
	else
		rm -r /home/web/html/$yuming >/dev/null 2>&1
		rm /home/web/conf.d/$yuming.conf >/dev/null 2>&1
		rm /home/web/certs/${yuming}_key.pem >/dev/null 2>&1
		rm /home/web/certs/${yuming}_cert.pem >/dev/null 2>&1
		docker restart nginx >/dev/null 2>&1

		#		dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
		#		docker exec mysql mysql -u root -p"$dbrootpasswd" -e "DROP DATABASE $dbname;" 2>/dev/null

		echo -e "${hong}检测到域名证书申请失败，请检测域名是否正确解析或更换域名重新尝试！${bai}"
	fi

}

repeat_add_yuming() {

	domain_regex="^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
	if [[ $yuming =~ $domain_regex ]]; then
		echo "域名格式正确"
	else
		echo "域名格式不正确，请重新输入"
		break_end
		s1xu
	fi

	if [ -e /home/web/conf.d/$yuming.conf ]; then
		echo -e "${huang}当前 ${yuming} 域名已被使用，请前往31站点管理，删除站点，再部署 ${webname} ！${bai}"
		break_end
		s1xu
	else
		echo "当前 ${yuming} 域名可用"
	fi

}

add_yuming() {
	ip_address
	echo -e "先将域名解析到本机IP: ${huang}$ipv4_address  $ipv6_address${bai}"
	read -p "请输入你解析的域名: " yuming
	repeat_add_yuming

}

add_db() {
	dbname=$(echo "$yuming" | sed -e 's/[^A-Za-z0-9]/_/g')
	dbname="${dbname}"

	dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	dbuse=$(grep -oP 'MYSQL_USER:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	dbusepasswd=$(grep -oP 'MYSQL_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	docker exec mysql mysql -u root -p"$dbrootpasswd" -e "CREATE DATABASE $dbname; GRANT ALL PRIVILEGES ON $dbname.* TO \"$dbuse\"@\"%\";"
}

reverse_proxy() {
	ip_address
	wget -O /home/web/conf.d/$yuming.confhttps://raw.githubusercontent.com/kyrxie/tools/main/nginx/reverse-proxy.conf
	sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
	sed -i "s/0.0.0.0/$ipv4_address/g" /home/web/conf.d/$yuming.conf
	sed -i "s/0000/$duankou/g" /home/web/conf.d/$yuming.conf
	docker restart nginx
}

restart_ldnmp() {
	docker exec nginx chmod -R 777 /var/www/html
	docker exec php chmod -R 777 /var/www/html
	docker exec php74 chmod -R 777 /var/www/html

	docker restart nginx
	docker restart php
	docker restart php74

}

has_ipv4_has_ipv6() {

	ip_address
	if [ -z "$ipv4_address" ]; then
		has_ipv4=false
	else
		has_ipv4=true
	fi

	if [ -z "$ipv6_address" ]; then
		has_ipv6=false
	else
		has_ipv6=true
	fi

}

docker_app() {
	has_ipv4_has_ipv6
	if docker inspect "$docker_name" &>/dev/null; then
		clear
		echo "$docker_name 已安装，访问地址: "
		if $has_ipv4; then
			echo "http:$ipv4_address:$docker_port"
		fi
		if $has_ipv6; then
			echo "http:[$ipv6_address]:$docker_port"
		fi
		echo ""
		echo "应用操作"
		echo "------------------------"
		echo "1. 更新应用             2. 卸载应用"
		echo "------------------------"
		echo "0. 返回上一级选单"
		echo "------------------------"
		read -p "请输入你的选择: " sub_choice

		case $sub_choice in
		1)
			clear
			docker rm -f "$docker_name"
			docker rmi -f "$docker_img"

			$docker_rum
			clear
			echo "$docker_name 已经安装完成"
			echo "------------------------"
			echo "您可以使用以下地址访问:"
			if $has_ipv4; then
				echo "http:$ipv4_address:$docker_port"
			fi
			if $has_ipv6; then
				echo "http:[$ipv6_address]:$docker_port"
			fi
			echo ""
			$docker_use
			$docker_passwd
			;;
		2)
			clear
			docker rm -f "$docker_name"
			docker rmi -f "$docker_img"
			rm -rf "/home/docker/$docker_name"
			echo "应用已卸载"
			;;
		0) ;;

		\
			*) ;;

		esac

	else
		clear
		echo "安装提示"
		echo "$docker_describe"
		echo "$docker_url"
		echo ""

		# 提示用户确认安装
		read -p "确定安装吗？(Y/N): " choice
		case "$choice" in
		[Yy])
			clear
			# 安装 Docker（请确保有 install_docker 函数）
			install_docker
			$docker_rum
			clear
			echo "$docker_name 已经安装完成"
			echo "------------------------"
			echo "您可以使用以下地址访问:"
			if $has_ipv4; then
				echo "http:$ipv4_address:$docker_port"
			fi
			if $has_ipv6; then
				echo "http:[$ipv6_address]:$docker_port"
			fi
			echo ""
			$docker_use
			$docker_passwd
			;;
		[Nn])
			# 用户选择不安装
			;;
		*)
			# 无效输入
			;;
		esac
	fi

}

#cluster_python3() {
#  cd ~/cluster/
#  curl -sS -O https://raw.githubusercontent.com/kejilion/python-for-vps/main/cluster/$py_task
#  python3 ~/cluster/$py_task
#}

tmux_run() {
	# Check if the session already exists
	tmux has-session -t "$SESSION_NAME" 2>/dev/null
	# $? is a special variable that holds the exit status of the last executed command
	if [ $? != 0 ]; then
		# Session doesn't exist, create a new one
		tmux new -s "$SESSION_NAME"
	else
		# Session exists, attach to it
		tmux attach-session -t "$SESSION_NAME"
	fi
}

f2b_status() {
	docker restart fail2ban
	sleep 3
	docker exec -it fail2ban fail2ban-client status
}

f2b_status_xxx() {
	docker exec -it fail2ban fail2ban-client status $xxx
}

f2b_install_sshd() {

	docker run -d \
		--name=fail2ban \
		--net=host \
		--cap-add=NET_ADMIN \
		--cap-add=NET_RAW \
		-e PUID=1000 \
		-e PGID=1000 \
		-e TZ=Etc/UTC \
		-e VERBOSITY=-vv \
		-v /path/to/fail2ban/config:/config \
		-v /var/log:/var/log:ro \
		-v /home/web/log/nginx/:/remotelogs/nginx:ro \
		--restart unless-stopped \
		lscr.io/linuxserver/fail2ban:latest

	sleep 3
	if grep -q 'Alpine' /etc/issue; then
		cd /path/to/fail2ban/config/fail2ban/filter.d
		curl -sS -O https://raw.githubusercontent.com/kyrxie/tools/main/fail2ban/alpine-sshd.conf
		curl -sS -O https://raw.githubusercontent.com/kyrxie/tools/main/fail2ban/alpine-sshd-ddos.conf
		cd /path/to/fail2ban/config/fail2ban/jail.d/
		curl -sS -O https://raw.githubusercontent.com/kyrxie/tools/main/fail2ban/alpine-ssh.conf
	elif grep -qi 'CentOS' /etc/redhat-release; then
		cd /path/to/fail2ban/config/fail2ban/jail.d/
		curl -sS -O https://raw.githubusercontent.com/kyrxie/tools/main/fail2ban/centos-ssh.conf
	else
		install rsyslog
		systemctl start rsyslog
		systemctl enable rsyslog
		cd /path/to/fail2ban/config/fail2ban/jail.d/
		curl -sS -O https://raw.githubusercontent.com/kyrxie/tools/main/fail2ban/linux-ssh.conf
	fi
}

f2b_sshd() {
	if grep -q 'Alpine' /etc/issue; then
		xxx=alpine-sshd
		f2b_status_xxx
	elif grep -qi 'CentOS' /etc/redhat-release; then
		xxx=centos-sshd
		f2b_status_xxx
	else
		xxx=linux-sshd
		f2b_status_xxx
	fi
}

server_reboot() {

	read -p "$(echo -e "${huang}现在重启服务器吗？(Y/N): ${bai}")" rboot
	case "$rboot" in
	[Yy])
		echo "已重启"
		reboot
		;;
	[Nn])
		echo "已取消"
		;;
	*)
		echo "无效的选择，请输入 Y 或 N。"
		;;
	esac

}

output_status() {
	output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        NR > 2 { rx_total += $2; tx_total += $10 }
        END {
            rx_units = "Bytes";
            tx_units = "Bytes";
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "KB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "MB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "GB"; }

            if (tx_total > 1024) { tx_total /= 1024; tx_units = "KB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "MB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "GB"; }

            printf("总接收: %.2f %s\n总发送: %.2f %s\n", rx_total, rx_units, tx_total, tx_units);
        }' /proc/net/dev)

}

ldnmp_install_status_one() {

	if docker inspect "php" &>/dev/null; then
		echo -e "${huang}LDNMP环境已安装。无法再次安装。可以使用37. 更新LDNMP环境${bai}"
		break_end
		s1xu
	else
		echo
	fi

}

ldnmp_install_status() {

	if docker inspect "php" &>/dev/null; then
		echo "LDNMP环境已安装，开始部署 $webname"
	else
		echo -e "${huang}LDNMP环境未安装，请先安装LDNMP环境，再部署网站${bai}"
		break_end
		s1xu

	fi

}

nginx_install_status() {

	if docker inspect "nginx" &>/dev/null; then
		echo "nginx环境已安装，开始部署 $webname"
	else
		echo -e "${huang}nginx未安装，请先安装nginx环境，再部署网站${bai}"
		break_end
		s1xu

	fi

}

ldnmp_web_on() {
	clear
	echo "您的 $webname 搭建好了！"
	echo "https://$yuming"
	echo "------------------------"
	echo "$webname 安装信息如下: "

}

nginx_web_on() {
	clear
	echo "您的 $webname 搭建好了！"
	echo "https://$yuming"

}

install_panel() {
	if $lujing; then
		clear
		echo "$panelname 已安装，应用操作"
		echo ""
		echo "------------------------"
		echo "1. 管理$panelname          2. 卸载$panelname"
		echo "------------------------"
		echo "0. 返回上一级选单"
		echo "------------------------"
		read -p "请输入你的选择: " sub_choice

		case $sub_choice in
		1)
			clear
			$gongneng1
			$gongneng1_1
			;;
		2)
			clear
			$gongneng2
			$gongneng2_1
			$gongneng2_2
			;;
		0)
			return
			;;
		*)
			return
			;;
		esac
	else
		clear
		echo "安装提示"
		echo "如果您已经安装了其他面板工具或者LDNMP建站环境，建议先卸载，再安装 $panelname！"
		echo "会根据系统自动安装，支持Debian，Ubuntu，Centos"
		echo "官网介绍: $panelurl "
		echo ""

		read -p "确定安装 $panelname 吗？(Y/N): " choice
		case "$choice" in
		[Yy])
			iptables_open
			install wget
			if grep -q 'Alpine' /etc/issue; then
				$ubuntu_mingling
				$ubuntu_mingling2
			elif grep -qi 'CentOS' /etc/redhat-release; then
				$centos_mingling
				$centos_mingling2
			elif grep -qi 'Ubuntu' /etc/os-release; then
				$ubuntu_mingling
				$ubuntu_mingling2
			elif grep -qi 'Debian' /etc/os-release; then
				$ubuntu_mingling
				$ubuntu_mingling2
			else
				echo "Unsupported OS"
			fi
			;;
		[Nn]) ;;

		*) ;;

		esac

	fi

}

current_timezone() {
	if grep -q 'Alpine' /etc/issue; then
		date +"%Z %z"
	else
		timedatectl | grep "Time zone" | awk '{print $3}'
	fi

}

set_timedate() {
	shiqu="$1"
	if grep -q 'Alpine' /etc/issue; then
		install tzdata
		cp /usr/share/zoneinfo/${shiqu} /etc/localtime
		hwclock --systohc
	else
		timedatectl set-timezone ${shiqu}
	fi
}

linux_update() {

	# Update system on Debian-based systems
	if [ -f "/etc/debian_version" ]; then
		apt update -y && DEBIAN_FRONTEND=noninteractive apt full-upgrade -y
	fi

	# Update system on Red Hat-based systems
	if [ -f "/etc/redhat-release" ]; then
		yum -y update
	fi

	# Update system on Alpine Linux
	if [ -f "/etc/alpine-release" ]; then
		apk update && apk upgrade
	fi

}

linux_clean() {
	clean_debian() {
		apt autoremove --purge -y
		apt clean -y
		apt autoclean -y
		apt remove --purge $(dpkg -l | awk '/^rc/ {print $2}') -y
		journalctl --rotate
		journalctl --vacuum-time=1s
		journalctl --vacuum-size=50M
		apt remove --purge $(dpkg -l | awk '/^ii linux-(image|headers)-[^ ]+/{print $2}' | grep -v $(uname -r | sed 's/-.*//') | xargs) -y
	}

	clean_redhat() {
		yum autoremove -y
		yum clean all
		journalctl --rotate
		journalctl --vacuum-time=1s
		journalctl --vacuum-size=50M
		yum remove $(rpm -q kernel | grep -v $(uname -r)) -y
	}

	clean_alpine() {
		apk del --purge $(apk info --installed | awk '{print $1}' | grep -v $(apk info --available | awk '{print $1}'))
		apk autoremove
		apk cache clean
		rm -rf /var/log/*
		rm -rf /var/cache/apk/*

	}

	# Main script
	if [ -f "/etc/debian_version" ]; then
		# Debian-based systems
		clean_debian
	elif [ -f "/etc/redhat-release" ]; then
		# Red Hat-based systems
		clean_redhat
	elif [ -f "/etc/alpine-release" ]; then
		# Alpine Linux
		clean_alpine
	fi

}

bbr_on() {

	cat >/etc/sysctl.conf <<EOF
net.core.default_qdisc=fq_pie
net.ipv4.tcp_congestion_control=bbr
EOF
	sysctl -p

}

set_dns() {

	# 检查机器是否有IPv6地址
	ipv6_available=0
	if [[ $(ip -6 addr | grep -c "inet6") -gt 0 ]]; then
		ipv6_available=1
	fi

	echo "nameserver $dns1_ipv4" >/etc/resolv.conf
	echo "nameserver $dns2_ipv4" >>/etc/resolv.conf

	if [[ $ipv6_available -eq 1 ]]; then
		echo "nameserver $dns1_ipv6" >>/etc/resolv.conf
		echo "nameserver $dns2_ipv6" >>/etc/resolv.conf
	fi

	echo "DNS地址已更新"
	echo "------------------------"
	cat /etc/resolv.conf
	echo "------------------------"

}

restart_ssh() {

	if command -v dnf &>/dev/null; then
		systemctl restart sshd
	elif command -v yum &>/dev/null; then
		systemctl restart sshd
	elif command -v apt &>/dev/null; then
		service ssh restart
	elif command -v apk &>/dev/null; then
		service sshd restart
	else
		echo "未知的包管理器!"
		return 1
	fi

}

new_ssh_port() {

	# 备份 SSH 配置文件
	cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

	sed -i 's/^\s*#\?\s*Port/Port/' /etc/ssh/sshd_config

	# 替换 SSH 配置文件中的端口号
	sed -i "s/Port [0-9]\+/Port $new_port/g" /etc/ssh/sshd_config

	rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*

	# 重启 SSH 服务
	restart_ssh
	echo "SSH 端口已修改为: $new_port"

	iptables_open
	remove iptables-persistent ufw firewalld iptables-services >/dev/null 2>&1

}

add_sshkey() {

	# ssh-keygen -t rsa -b 4096 -C "xxxx@gmail.com" -f /root/.ssh/sshkey -N ""
	ssh-keygen -t ed25519 -C "xxxx@gmail.com" -f /root/.ssh/sshkey -N ""

	cat ~/.ssh/sshkey.pub >>~/.ssh/authorized_keys
	chmod 600 ~/.ssh/authorized_keys

	ip_address
	echo -e "私钥信息已生成，务必复制保存，可保存成 ${huang}${ipv4_address}_ssh.key${bai} 文件，用于以后的SSH登录"

	echo "--------------------------------"
	cat ~/.ssh/sshkey
	echo "--------------------------------"

	sed -i -e 's/^\s*#\?\s*PermitRootLogin .*/PermitRootLogin prohibit-password/' \
		-e 's/^\s*#\?\s*PasswordAuthentication .*/PasswordAuthentication no/' \
		-e 's/^\s*#\?\s*PubkeyAuthentication .*/PubkeyAuthentication yes/' \
		-e 's/^\s*#\?\s*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
	rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*
	echo -e "${lv}ROOT私钥登录已开启，已关闭ROOT密码登录，重连将会生效${bai}"

}

add_sshpasswd() {

	echo "设置你的ROOT密码"
	passwd
	sed -i 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
	sed -i 's/^\s*#\?\s*PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
	rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*
	restart_ssh
	echo -e "${lv}ROOT登录设置完毕！${bai}"

}

root_use() {
	clear
	[ "$EUID" -ne 0 ] && echo -e "${huang}请注意，该功能需要root用户才能运行！${bai}" && break_end && s1xu
}

while true; do
	clear

	echo -e "${s1xu}____________________________ "
	echo "         _                  "
	echo "  ___   / |  __  __   _   _ "
	echo " / __|  | |  \ \/ /  | | | |"
	echo " \__ \  | |   >  <   | |_| |"
	echo " |___/  |_|  /_/\_\   \____|"
	echo "____________________________ "

	echo -e "${s1xu}s1xu一键脚本工具 v$sh_v （支持Ubuntu/Debian/CentOS/Alpine系统）${bai}"
	echo -e "${s1xu}-输入${huang}xx${s1xu}可快速启动此脚本-${bai}"
	echo "------------------------"
	echo "1. 系统信息查询"
	echo "2. 系统更新"
	echo "3. 系统清理"
	echo "4. Docker管理 ▶ "
	echo "5. WARP管理 ▶ "
	echo "6. 测试脚本合集 ▶ "
	echo "7. 甲骨文云脚本合集 ▶ "
	echo -e "${huang}8. LDNMP建站 ▶ ${bai}"
	echo "9. 面板工具 ▶ "
	echo "11. 我的工作区 ▶ "
	echo "12. 系统工具 ▶ "
	echo "------------------------"
	echo "00. 脚本更新"
	echo "------------------------"
	echo "0. 退出脚本"
	echo "------------------------"
	read -p "请输入你的选择: " choice

	case $choice in
	1)
		clear
		# 函数: 获取IPv4和IPv6地址
		ip_address

		if [ "$(uname -m)" == "x86_64" ]; then
			cpu_info=$(cat /proc/cpuinfo | grep 'model name' | uniq | sed -e 's/model name[[:space:]]*: //')
		else
			cpu_info=$(lscpu | grep 'BIOS Model name' | awk -F': ' '{print $2}' | sed 's/^[ \t]*//')
		fi

		if [ -f /etc/alpine-release ]; then
			# Alpine Linux 使用以下命令获取 CPU 使用率
			cpu_usage_percent=$(top -bn1 | grep '^CPU' | awk '{print " "$4}' | cut -c 1-2)
		else
			# 其他系统使用以下命令获取 CPU 使用率
			cpu_usage_percent=$(top -bn1 | grep "Cpu(s)" | awk '{print " "$2}')
		fi

		cpu_cores=$(nproc)

		mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2f MB (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')

		disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')

		country=$(curl -s ipinfo.io/country)
		city=$(curl -s ipinfo.io/city)

		isp_info=$(curl -s ipinfo.io/org)

		cpu_arch=$(uname -m)

		hostname=$(hostname)

		kernel_version=$(uname -r)

		congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
		queue_algorithm=$(sysctl -n net.core.default_qdisc)

		# 尝试使用 lsb_release 获取系统信息
		os_info=$(lsb_release -ds 2>/dev/null)

		# 如果 lsb_release 命令失败，则尝试其他方法
		if [ -z "$os_info" ]; then
			# 检查常见的发行文件
			if [ -f "/etc/os-release" ]; then
				os_info=$(source /etc/os-release && echo "$PRETTY_NAME")
			elif [ -f "/etc/debian_version" ]; then
				os_info="Debian $(cat /etc/debian_version)"
			elif [ -f "/etc/redhat-release" ]; then
				os_info=$(cat /etc/redhat-release)
			else
				os_info="Unknown"
			fi
		fi

		output_status

		current_time=$(date "+%Y-%m-%d %I:%M %p")

		swap_used=$(free -m | awk 'NR==3{print $3}')
		swap_total=$(free -m | awk 'NR==3{print $2}')

		if [ "$swap_total" -eq 0 ]; then
			swap_percentage=0
		else
			swap_percentage=$((swap_used * 100 / swap_total))
		fi

		swap_info="${swap_used}MB/${swap_total}MB (${swap_percentage}%)"

		runtime=$(cat /proc/uptime | awk -F. '{run_days=int($1 / 86400);run_hours=int(($1 % 86400) / 3600);run_minutes=int(($1 % 3600) / 60); if (run_days > 0) printf("%d天 ", run_days); if (run_hours > 0) printf("%d时 ", run_hours); printf("%d分\n", run_minutes)}')

		timezone=$(current_timezone)

		echo ""
		echo "系统信息查询"
		echo "------------------------"
		echo "主机名: $hostname"
		echo "运营商: $isp_info"
		echo "------------------------"
		echo "系统版本: $os_info"
		echo "Linux版本: $kernel_version"
		echo "------------------------"
		echo "CPU架构: $cpu_arch"
		echo "CPU型号: $cpu_info"
		echo "CPU核心数: $cpu_cores"
		echo "------------------------"
		echo "CPU占用: $cpu_usage_percent%"
		echo "物理内存: $mem_info"
		echo "虚拟内存: $swap_info"
		echo "硬盘占用: $disk_info"
		echo "------------------------"
		echo "$output"
		echo "------------------------"
		echo "网络拥堵算法: $congestion_algorithm $queue_algorithm"
		echo "------------------------"
		echo "公网IPv4地址: $ipv4_address"
		echo "公网IPv6地址: $ipv6_address"
		echo "------------------------"
		echo "地理位置: $country $city"
		echo "系统时区: $timezone"
		echo "系统时间: $current_time"
		echo "------------------------"
		echo "系统运行时长: $runtime"
		echo

		;;

	2)
		clear
		linux_update
		;;

	3)
		clear
		linux_clean
		;;

	4)
		while true; do
			clear
			echo "▶ Docker管理器"
			echo "------------------------"
			echo "1. 安装更新Docker环境"
			echo "------------------------"
			echo "2. 查看Docker全局状态"
			echo "------------------------"
			echo "3. Docker容器管理 ▶"
			echo "4. Docker镜像管理 ▶"
			echo "5. Docker网络管理 ▶"
			echo "6. Docker卷管理 ▶"
			echo "------------------------"
			echo "7. 清理无用的docker容器和镜像网络数据卷"
			echo "------------------------"
			echo "8. 更换Docker源"
			echo "9. 编辑daemon.json文件"
			echo "------------------------"
			echo "11. 开启Docker-ipv6访问"
			echo "12. 关闭Docker-ipv6访问"
			echo "------------------------"
			echo "20. 卸载Docker环境"
			echo "------------------------"
			echo "0. 返回主菜单"
			echo "------------------------"
			read -p "请输入你的选择: " sub_choice

			case $sub_choice in
			1)
				clear
				install_add_docker

				;;
			2)
				clear
				echo "Docker版本"
				docker -v
				docker compose version

				echo ""
				echo "Docker镜像列表"
				docker image ls
				echo ""
				echo "Docker容器列表"
				docker ps -a
				echo ""
				echo "Docker卷列表"
				docker volume ls
				echo ""
				echo "Docker网络列表"
				docker network ls
				echo ""

				;;
			3)
				while true; do
					clear
					echo "Docker容器列表"
					docker ps -a
					echo ""
					echo "容器操作"
					echo "------------------------"
					echo "1. 创建新的容器"
					echo "------------------------"
					echo "2. 启动指定容器             6. 启动所有容器"
					echo "3. 停止指定容器             7. 暂停所有容器"
					echo "4. 删除指定容器             8. 删除所有容器"
					echo "5. 重启指定容器             9. 重启所有容器"
					echo "------------------------"
					echo "11. 进入指定容器           12. 查看容器日志           13. 查看容器网络"
					echo "------------------------"
					echo "0. 返回上一级选单"
					echo "------------------------"
					read -p "请输入你的选择: " sub_choice

					case $sub_choice in
					1)
						read -p "请输入创建命令: " dockername
						$dockername
						;;

					2)
						read -p "请输入容器名: " dockername
						docker start $dockername
						;;
					3)
						read -p "请输入容器名: " dockername
						docker stop $dockername
						;;
					4)
						read -p "请输入容器名: " dockername
						docker rm -f $dockername
						;;
					5)
						read -p "请输入容器名: " dockername
						docker restart $dockername
						;;
					6)
						docker start $(docker ps -a -q)
						;;
					7)
						docker stop $(docker ps -q)
						;;
					8)
						read -p "$(echo -e "${hong}确定删除所有容器吗？(Y/N): ${bai}")" choice
						case "$choice" in
						[Yy])
							docker rm -f $(docker ps -a -q)
							;;
						[Nn]) ;;

						*)
							echo "无效的选择，请输入 Y 或 N。"
							;;
						esac
						;;
					9)
						docker restart $(docker ps -q)
						;;
					11)
						read -p "请输入容器名: " dockername
						docker exec -it $dockername /bin/sh
						break_end
						;;
					12)
						read -p "请输入容器名: " dockername
						docker logs $dockername
						break_end
						;;
					13)
						echo ""
						container_ids=$(docker ps -q)

						echo "------------------------------------------------------------"
						printf "%-25s %-25s %-25s\n" "容器名称" "网络名称" "IP地址"

						for container_id in $container_ids; do
							container_info=$(docker inspect --format '{{ .Name }}{{ range $network, $config := .NetworkSettings.Networks }} {{ $network }} {{ $config.IPAddress }}{{ end }}' "$container_id")

							container_name=$(echo "$container_info" | awk '{print $1}')
							network_info=$(echo "$container_info" | cut -d' ' -f2-)

							while IFS= read -r line; do
								network_name=$(echo "$line" | awk '{print $1}')
								ip_address=$(echo "$line" | awk '{print $2}')

								printf "%-20s %-20s %-15s\n" "$container_name" "$network_name" "$ip_address"
							done <<<"$network_info"
						done

						break_end
						;;

					0)
						break
						;;

					*)
						break
						;;
					esac
				done
				;;
			4)
				while true; do
					clear
					echo "Docker镜像列表"
					docker image ls
					echo ""
					echo "镜像操作"
					echo "------------------------"
					echo "1. 获取指定镜像             3. 删除指定镜像"
					echo "2. 更新指定镜像             4. 删除所有镜像"
					echo "------------------------"
					echo "0. 返回上一级选单"
					echo "------------------------"
					read -p "请输入你的选择: " sub_choice

					case $sub_choice in
					1)
						read -p "请输入镜像名: " dockername
						docker pull $dockername
						;;
					2)
						read -p "请输入镜像名: " dockername
						docker pull $dockername
						;;
					3)
						read -p "请输入镜像名: " dockername
						docker rmi -f $dockername
						;;
					4)
						read -p "$(echo -e "${hong}确定删除所有镜像吗？(Y/N): ${bai}")" choice
						case "$choice" in
						[Yy])
							docker rmi -f $(docker images -q)
							;;
						[Nn]) ;;

						\
							*)
							echo "无效的选择，请输入 Y 或 N。"
							;;
						esac
						;;
					0)
						break
						;;

					*)
						break
						;;
					esac
				done
				;;

			5)
				while true; do
					clear
					echo "Docker网络列表"
					echo "------------------------------------------------------------"
					docker network ls
					echo ""

					echo "------------------------------------------------------------"
					container_ids=$(docker ps -q)
					printf "%-25s %-25s %-25s\n" "容器名称" "网络名称" "IP地址"

					for container_id in $container_ids; do
						container_info=$(docker inspect --format '{{ .Name }}{{ range $network, $config := .NetworkSettings.Networks }} {{ $network }} {{ $config.IPAddress }}{{ end }}' "$container_id")

						container_name=$(echo "$container_info" | awk '{print $1}')
						network_info=$(echo "$container_info" | cut -d' ' -f2-)

						while IFS= read -r line; do
							network_name=$(echo "$line" | awk '{print $1}')
							ip_address=$(echo "$line" | awk '{print $2}')

							printf "%-20s %-20s %-15s\n" "$container_name" "$network_name" "$ip_address"
						done <<<"$network_info"
					done

					echo ""
					echo "网络操作"
					echo "------------------------"
					echo "1. 创建网络"
					echo "2. 加入网络"
					echo "3. 退出网络"
					echo "4. 删除网络"
					echo "------------------------"
					echo "0. 返回上一级选单"
					echo "------------------------"
					read -p "请输入你的选择: " sub_choice

					case $sub_choice in
					1)
						read -p "设置新网络名: " dockernetwork
						docker network create $dockernetwork
						;;
					2)
						read -p "加入网络名: " dockernetwork
						read -p "那些容器加入该网络: " dockername
						docker network connect $dockernetwork $dockername
						echo ""
						;;
					3)
						read -p "退出网络名: " dockernetwork
						read -p "那些容器退出该网络: " dockername
						docker network disconnect $dockernetwork $dockername
						echo ""
						;;

					4)
						read -p "请输入要删除的网络名: " dockernetwork
						docker network rm $dockernetwork
						;;
					0)
						break
						;;

					*)
						break
						;;
					esac
				done
				;;

			6)
				while true; do
					clear
					echo "Docker卷列表"
					docker volume ls
					echo ""
					echo "卷操作"
					echo "------------------------"
					echo "1. 创建新卷"
					echo "2. 删除卷"
					echo "------------------------"
					echo "0. 返回上一级选单"
					echo "------------------------"
					read -p "请输入你的选择: " sub_choice

					case $sub_choice in
					1)
						read -p "设置新卷名: " dockerjuan
						docker volume create $dockerjuan

						;;
					2)
						read -p "输入删除卷名: " dockerjuan
						docker volume rm $dockerjuan

						;;
					0)
						break
						;;

					*)
						break
						;;
					esac
				done
				;;
			7)
				clear
				read -p "$(echo -e "${huang}确定清理无用的镜像容器网络吗？(Y/N): ${bai}")" choice
				case "$choice" in
				[Yy])
					docker system prune -af --volumes
					;;
				[Nn]) ;;

				*)
					echo "无效的选择，请输入 Y 或 N。"
					;;
				esac
				;;
			8)
				clear
				bash <(curl -sSL https://linuxmirrors.cn/docker.sh)
				;;

			9)
				clear
				mkdir -p /etc/docker && vim /etc/docker/daemon.json
				if command -v dnf &>/dev/null || command -v yum &>/dev/null; then
					systemctl restart docker
				else
					service docker restart
				fi
				;;

			11)
				clear
				docker_ipv6_on
				;;

			12)
				clear
				docker_ipv6_off
				;;

			20)
				clear
				read -p "$(echo -e "${hong}确定卸载docker环境吗？(Y/N): ${bai}")" choice
				case "$choice" in
				[Yy])
					docker rm $(docker ps -a -q) && docker rmi $(docker images -q) && docker network prune
					remove docker >/dev/null 2>&1
					;;
				[Nn]) ;;

				*)
					echo "无效的选择，请输入 Y 或 N。"
					;;
				esac
				;;

			0)
				s1xu
				;;
			*)
				echo "无效的输入!"
				;;
			esac
			break_end

		done
		;;

	5)
		clear
		install wget
		wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh [option] [lisence/url/token]
		;;

	6)
		while true; do
			clear
			echo "▶ 测试脚本合集"
			echo ""
			echo "----IP及解锁状态检测-----------"
			echo "1. ChatGPT解锁状态检测"
			echo "2. Region流媒体解锁测试"
			echo "3. yeahwu流媒体解锁检测"
			echo "4. xykt_IP质量体检脚本"
			echo ""
			echo "----网络线路测速-----------"
			echo "11. besttrace三网回程延迟路由测试"
			echo "12. mtr_trace三网回程线路测试"
			echo "13. Superspeed三网测速"
			echo "14. nxtrace快速回程测试脚本"
			echo "15. nxtrace指定IP回程测试脚本"
			echo "16. ludashi2020三网线路测试"
			echo ""
			echo "----硬件性能测试----------"
			echo "21. yabs性能测试"
			echo "22. icu/gb5 CPU性能测试脚本"
			echo ""
			echo "----综合性测试-----------"
			echo "31. bench性能测试"
			echo "32. spiritysdx融合怪测评"
			echo ""
			echo "------------------------"
			echo "0. 返回主菜单"
			echo "------------------------"
			read -p "请输入你的选择: " sub_choice

			case $sub_choice in
			1)
				clear
				bash <(curl -Ls https://cdn.jsdelivr.net/gh/missuo/OpenAI-Checker/openai.sh)
				;;
			2)
				clear
				bash <(curl -L -s check.unlock.media)
				;;
			3)
				clear
				install wget
				wget -qO- https://github.com/yeahwu/check/raw/main/check.sh | bash
				;;
			4)
				clear
				bash <(curl -Ls IP.Check.Place)
				;;
			11)
				clear
				install wget
				wget -qO- git.io/besttrace | bash
				;;
			12)
				clear
				curl https://raw.githubusercontent.com/zhucaidan/mtr_trace/main/mtr_trace.sh | bash
				;;
			13)
				clear
				bash <(curl -Lso- https://git.io/superspeed_uxh)
				;;
			14)
				clear
				curl nxtrace.org/nt | bash
				nexttrace --fast-trace --tcp
				;;
			15)
				clear

				echo "可参考的IP列表"
				echo "------------------------"
				echo "北京电信: 219.141.136.12"
				echo "北京联通: 202.106.50.1"
				echo "北京移动: 221.179.155.161"
				echo "上海电信: 202.96.209.133"
				echo "上海联通: 210.22.97.1"
				echo "上海移动: 211.136.112.200"
				echo "广州电信: 58.60.188.222"
				echo "广州联通: 210.21.196.6"
				echo "广州移动: 120.196.165.24"
				echo "成都电信: 61.139.2.69"
				echo "成都联通: 119.6.6.6"
				echo "成都移动: 211.137.96.205"
				echo "湖南电信: 36.111.200.100"
				echo "湖南联通: 42.48.16.100"
				echo "湖南移动: 39.134.254.6"
				echo "------------------------"

				read -p "输入一个指定IP: " testip
				curl nxtrace.org/nt | bash
				nexttrace $testip
				;;

			16)
				clear
				curl https://raw.githubusercontent.com/ludashi2020/backtrace/main/install.sh -sSf | sh
				;;

			21)
				clear
				new_swap=1024
				add_swap
				curl -sL yabs.sh | bash -s -- -i -5
				;;
			22)
				clear
				new_swap=1024
				add_swap
				bash <(curl -sL bash.icu/gb5)
				;;

			31)
				clear
				curl -Lso- bench.sh | bash
				;;
			32)
				clear
				curl -L https://gitlab.com/spiritysdx/za/-/raw/main/ecs.sh -o ecs.sh && chmod +x ecs.sh && bash ecs.sh
				;;

			\
				0)
				s1xu

				;;
			*)
				echo "无效的输入!"
				;;
			esac
			break_end

		done
		;;

	7)
		while true; do
			clear
			echo "▶ 甲骨文云脚本合集"
			echo "------------------------"
			echo "1. 安装闲置机器活跃脚本"
			echo "2. 卸载闲置机器活跃脚本"
			echo "------------------------"
			echo "3. DD重装系统脚本"
			echo "------------------------"
			echo "4. 开启ROOT密码登录模式"
			echo "------------------------"
			echo "0. 返回主菜单"
			echo "------------------------"
			read -p "请输入你的选择: " sub_choice

			case $sub_choice in
			1)
				clear
				echo "活跃脚本: CPU占用10-20% 内存占用15% "
				read -p "确定安装吗？(Y/N): " choice
				case "$choice" in
				[Yy])

					install_docker

					docker run -itd --name=lookbusy --restart=always \
						-e TZ=Asia/Shanghai \
						-e CPU_UTIL=10-20 \
						-e CPU_CORE=1 \
						-e MEM_UTIL=15 \
						-e SPEEDTEST_INTERVAL=120 \
						fogforest/lookbusy
					;;
				[Nn]) ;;

				*)
					echo "无效的选择，请输入 Y 或 N。"
					;;
				esac
				;;
			2)
				clear
				docker rm -f lookbusy
				docker rmi fogforest/lookbusy
				;;

			3)
				clear
				echo "请备份数据，将为你重装系统，预计花费15分钟。"
				read -p "确定继续吗？(Y/N): " choice

				case "$choice" in
				[Yy])
					while true; do
						read -p "请选择要重装的系统:  1. Debian12 | 2. Ubuntu20.04 : " sys_choice

						case "$sys_choice" in
						1)
							xitong="-d 12"
							break # 结束循环
							;;
						2)
							xitong="-u 20.04"
							break # 结束循环
							;;
						*)
							echo "无效的选择，请重新输入。"
							;;
						esac
					done

					read -p "请输入你重装后的密码: " vpspasswd
					install wget
					bash <(wget --no-check-certificate -qO- 'https://raw.githubusercontent.com/MoeClub/Note/master/InstallNET.sh') $xitong -v 64 -p $vpspasswd -port 22
					;;
				[Nn])
					echo "已取消"
					;;
				*)
					echo "无效的选择，请输入 Y 或 N。"
					;;
				esac
				;;

			4)
				clear
				add_sshpasswd

				;;
			0)
				s1xu

				;;
			*)
				echo "无效的输入!"
				;;
			esac
			break_end

		done
		;;

	8)
		while true; do
			clear
			echo -e "${huang}▶ LDNMP建站${bai}"
			echo "------------------------"
			echo "1. 初始化环境"
			echo "------------------------"
			echo "21. 仅安装nginx"
			echo "22. 站点重定向"
			echo "23. 站点反向代理-IP+端口"
			echo "24. 站点反向代理-域名"
			echo "25. 自定义静态站点"
			echo "26. 安装Halo博客网站"
			echo "------------------------"
			echo "31. 站点数据管理"
			echo "32. 备份全站数据"
			echo "33. 定时远程备份"
			echo "------------------------"
			echo "35. 站点防御程序"
			echo "------------------------"
			echo "36. 优化LDNMP环境"
			echo "------------------------"
			echo "0. 返回主菜单"
			echo "------------------------"
			read -p "请输入你的选择: " sub_choice

			case $sub_choice in
			1)
				root_use
				#        ldnmp_install_status_one
				check_port
				install_dependency
				install_docker
				install_certbot

				# 创建必要的目录和文件
				cd /home && mkdir -p web/html web/mysql web/certs web/conf.d web/redis web/log/nginx && touch web/docker-compose.yml

				wget -O /home/web/nginx.conf https://raw.githubusercontent.com/kyrxie/tools/main/nginx/nginx10.conf
				wget -O /home/web/conf.d/default.conf https://raw.githubusercontent.com/kyrxie/tools/main/nginx/default10.conf
				default_server_ssl

				#        wget -O /home/web/docker-compose.yml https://raw.githubusercontent.com/kejilion/docker/main/LNMP-docker-compose-10.yml
				#
				#        dbrootpasswd=$(openssl rand -base64 16) && dbuse=$(openssl rand -hex 4) && dbusepasswd=$(openssl rand -base64 8)
				#
				#        # 在 docker-compose.yml 文件中进行替换
				#        sed -i "s#webroot#$dbrootpasswd#g" /home/web/docker-compose.yml
				#        sed -i "s#kejilionYYDS#$dbusepasswd#g" /home/web/docker-compose.yml
				#        sed -i "s#kejilion#$dbuse#g" /home/web/docker-compose.yml

				#        install_ldnmp

				;;

			21)
				root_use
				check_port
				install_dependency
				install_docker
				install_certbot

				cd /home && mkdir -p web/html web/mysql web/certs web/conf.d web/redis web/log/nginx && touch web/docker-compose.yml

				wget -O /home/web/nginx.conf https://raw.githubusercontent.com/kyrxie/tools/main/nginx/nginx10.conf
				wget -O /home/web/conf.d/default.conf https://raw.githubusercontent.com/kyrxie/tools/main/nginx/default10.conf

				default_server_ssl
				docker rm -f nginx >/dev/null 2>&1
				docker rmi nginx nginx:alpine >/dev/null 2>&1
				docker run -d \
					--name nginx \
					--restart always \
					-p 80:80 \
					-p 443:443 \
					-p 443:443/udp \
					-v /home/web/nginx.conf:/etc/nginx/nginx.conf \
					-v /home/web/conf.d:/etc/nginx/conf.d \
					-v /home/web/certs:/etc/nginx/certs \
					-v /home/web/html:/var/www/html \
					-v /home/web/log/nginx:/var/log/nginx \
					nginx:alpine

				clear
				nginx_version=$(docker exec nginx nginx -v 2>&1)
				nginx_version=$(echo "$nginx_version" | grep -oP "nginx/\K[0-9]+\.[0-9]+\.[0-9]+")
				echo "nginx已安装完成"
				echo -e "当前版本: ${huang}v$nginx_version${bai}"
				echo ""
				;;

			22)
				clear
				webname="站点重定向"
				nginx_install_status
				ip_address
				add_yuming
				read -p "请输入跳转域名: " reverseproxy

				install_ssltls

				wget -O /home/web/conf.d/$yuming.conf https://raw.githubusercontent.com/kyrxie/tools/main/nginx/rewrite.conf
				sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
				sed -i "s/proxy.com/$reverseproxy/g" /home/web/conf.d/$yuming.conf

				docker restart nginx

				nginx_web_on
				nginx_status
				;;

			23)
				clear
				webname="反向代理-IP+端口"
				nginx_install_status
				ip_address
				add_yuming
				read -p "请输入你的反代IP: " reverseproxy
				read -p "请输入你的反代端口: " port

				install_ssltls

				wget -O /home/web/conf.d/$yuming.conf https://raw.githubusercontent.com/kyrxie/tools/main/nginx/reverse-proxy.conf
				sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
				sed -i "s/0.0.0.0/$reverseproxy/g" /home/web/conf.d/$yuming.conf
				sed -i "s/0000/$port/g" /home/web/conf.d/$yuming.conf

				docker restart nginx

				nginx_web_on
				nginx_status
				;;

			24)
				clear
				webname="反向代理-域名"
				nginx_install_status
				ip_address
				add_yuming
				echo -e "域名格式: ${huang}http://www.google.com${bai}"
				read -p "请输入你的反代域名: " proxy_domain

				install_ssltls

				wget -O /home/web/conf.d/$yuming.conf https://raw.githubusercontent.com/kyrxie/tools/main/nginx/reverse-proxy-domain.conf
				sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
				sed -i "s|fandaicom|$proxy_domain|g" /home/web/conf.d/$yuming.conf

				docker restart nginx

				nginx_web_on
				nginx_status
				;;

			25)
				clear
				webname="静态站点"
				nginx_install_status
				add_yuming
				install_ssltls

				wget -O /home/web/conf.d/$yuming.conf https://raw.githubusercontent.com/kyrxie/tools/main/nginx/html.conf
				sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf

				cd /home/web/html
				mkdir $yuming
				cd $yuming

				clear
				echo -e "[${huang}1/2${bai}] 上传静态源码"
				echo "-------------"
				echo "目前只允许上传zip格式的源码包，请将源码包放到/home/web/html/${yuming}目录下"
				read -p "也可以输入下载链接，远程下载源码包，直接回车将跳过远程下载： " url_download

				if [ -n "$url_download" ]; then
					wget "$url_download"
				fi

				unzip $(ls -t *.zip | head -n 1)
				rm -f $(ls -t *.zip | head -n 1)

				clear
				echo -e "[${huang}2/2${bai}] index.html所在路径"
				echo "-------------"
				find "$(realpath .)" -name "index.html" -print

				read -p "请输入index.html的路径，类似（/home/web/html/$yuming/index/）： " index_lujing

				sed -i "s#root /var/www/html/$yuming/#root $index_lujing#g" /home/web/conf.d/$yuming.conf
				sed -i "s#/home/web/#/var/www/#g" /home/web/conf.d/$yuming.conf

				docker exec nginx chmod -R 777 /var/www/html
				docker restart nginx

				nginx_web_on
				nginx_status
				;;

			26)
				clear
				webname="halo"
				nginx_install_status
				add_yuming
				install_ssltls

				docker run -d --name halo --restart always -p 8010:8090 -v /home/web/html/$yuming/.halo2:/root/.halo2 halohub/halo:2
				duankou=8010
				reverse_proxy

				nginx_web_on
				nginx_status
				;;

			31)
				root_use
				while true; do
					clear
					echo "LDNMP环境"
					echo "------------------------"
					ldnmp_v

					# ls -t /home/web/conf.d | sed 's/\.[^.]*$//'
					echo "站点信息                      证书到期时间"
					echo "------------------------"
					for cert_file in /home/web/certs/*_cert.pem; do
						domain=$(basename "$cert_file" | sed 's/_cert.pem//')
						if [ -n "$domain" ]; then
							expire_date=$(openssl x509 -noout -enddate -in "$cert_file" | awk -F'=' '{print $2}')
							formatted_date=$(date -d "$expire_date" '+%Y-%m-%d')
							printf "%-30s%s\n" "$domain" "$formatted_date"
						fi
					done

					echo "------------------------"
					echo ""
					echo "数据库信息"
					echo "------------------------"
					dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
					docker exec mysql mysql -u root -p"$dbrootpasswd" -e "SHOW DATABASES;" 2>/dev/null | grep -Ev "Database|information_schema|mysql|performance_schema|sys"

					echo "------------------------"
					echo ""
					echo "站点目录"
					echo "------------------------"
					echo -e "数据 ${hui}/home/web/html${bai}     证书 ${hui}/home/web/certs${bai}     配置 ${hui}/home/web/conf.d${bai}"
					echo "------------------------"
					echo ""
					echo "操作"
					echo "------------------------"
					echo "1. 申请/更新域名证书"
					echo "3. 清理站点缓存                    4. 查看站点分析报告"
					echo "5. 查看全局配置                    6. 查看站点配置"
					echo "------------------------"
					echo "7. 删除指定站点                    8. 删除指定数据库"
					echo "------------------------"
					echo "0. 返回上一级选单"
					echo "------------------------"
					read -p "请输入你的选择: " sub_choice
					case $sub_choice in
					1)
						read -p "请输入你的域名: " yuming
						install_ssltls

						;;

					2)
						read -p "请输入旧域名: " oddyuming
						read -p "请输入新域名: " yuming
						install_ssltls
						mv /home/web/conf.d/$oddyuming.conf /home/web/conf.d/$yuming.conf
						sed -i "s/$oddyuming/$yuming/g" /home/web/conf.d/$yuming.conf
						mv /home/web/html/$oddyuming /home/web/html/$yuming

						rm /home/web/certs/${oddyuming}_key.pem
						rm /home/web/certs/${oddyuming}_cert.pem

						docker restart nginx

						;;
					3)
						docker exec -it nginx rm -rf /var/cache/nginx
						docker restart nginx
						docker exec php php -r 'opcache_reset();'
						docker restart php
						docker exec php74 php -r 'opcache_reset();'
						docker restart php74
						;;
					4)
						install goaccess
						goaccess --log-format=COMBINED /home/web/log/nginx/access.log

						;;

					5)
						install nano
						nano /home/web/nginx.conf
						docker restart nginx
						;;

					6)
						read -p "查看站点配置，请输入你的域名: " yuming
						install nano
						nano /home/web/conf.d/$yuming.conf
						docker restart nginx
						;;

					7)
						read -p "删除站点数据目录，请输入你的域名: " yuming
						rm -r /home/web/html/$yuming
						rm /home/web/conf.d/$yuming.conf
						rm /home/web/certs/${yuming}_key.pem
						rm /home/web/certs/${yuming}_cert.pem
						docker restart nginx
						;;
					8)
						read -p "删除站点数据库，请输入数据库名: " shujuku
						dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
						docker exec mysql mysql -u root -p"$dbrootpasswd" -e "DROP DATABASE $shujuku;" 2>/dev/null
						;;
					0)
						break
						;;
					*)
						break
						;;
					esac
				done

				;;
			32)
				clear
				cd /home/ && tar czvf web_$(date +"%Y%m%d%H%M%S").tar.gz web

				while true; do
					clear
					read -p "要传送文件到远程服务器吗？(Y/N): " choice
					case "$choice" in
					[Yy])
						read -p "请输入远端服务器IP:  " remote_ip
						if [ -z "$remote_ip" ]; then
							echo "错误: 请输入远端服务器IP。"
							continue
						fi
						latest_tar=$(ls -t /home/*.tar.gz | head -1)
						if [ -n "$latest_tar" ]; then
							ssh-keygen -f "/root/.ssh/known_hosts" -R "$remote_ip"
							sleep 2 # 添加等待时间
							scp -o StrictHostKeyChecking=no "$latest_tar" "root@$remote_ip:/home/"
							echo "文件已传送至远程服务器home目录。"
						else
							echo "未找到要传送的文件。"
						fi
						break
						;;
					[Nn])
						break
						;;
					*)
						echo "无效的选择，请输入 Y 或 N。"
						;;
					esac
				done
				;;

			33)
				clear
				read -p "输入远程服务器Port: " useport
				read -p "输入远程服务器IP: " useip
				read -p "输入远程服务器密码: " usepasswd

				cd ~
				wget -O ${useip}_backup.sh https://raw.githubusercontent.com/kyrxie/tools/main/backup/backup.sh >/dev/null 2>&1
				chmod +x ${useip}_backup.sh

				sed -i "s/22/$useport/g" ${useip}_backup.sh
				sed -i "s/0.0.0.0/$useip/g" ${useip}_backup.sh
				sed -i "s/123456/$usepasswd/g" ${useip}_backup.sh

				echo "------------------------"
				echo "1. 每周备份                 2. 每天备份"
				read -p "请输入你的选择: " dingshi

				case $dingshi in
				1)
					read -p "选择每周备份的星期几 (0-6，0代表星期日): " weekday
					(
						crontab -l
						echo "0 0 * * $weekday ./${useip}_backup.sh"
					) | crontab - >/dev/null 2>&1
					;;
				2)
					read -p "选择每天备份的时间（小时，0-23）: " hour
					(
						crontab -l
						echo "0 $hour * * * ./${useip}_backup.sh"
					) | crontab - >/dev/null 2>&1
					;;
				*)
					break # 跳出
					;;
				esac

				install sshpass

				;;

			34)
				root_use
				echo "请确认home目录中已经放置网站备份的gz压缩包，按任意键继续……"
				read -n 1 -s -r -p ""
				echo "开始解压……"
				cd /home/ && ls -t /home/*.tar.gz | head -1 | xargs -I {} tar -xzf {}
				check_port
				install_dependency
				install_docker
				install_certbot

#				install_ldnmp

				;;

			35)

				if docker inspect fail2ban &>/dev/null; then
					while true; do
						clear
						echo "服务器防御程序已启动"
						echo "------------------------"
						echo "1. 开启SSH防暴力破解              2. 关闭SSH防暴力破解"
						echo "3. 开启网站保护                   4. 关闭网站保护"
						echo "------------------------"
						echo "5. 查看SSH拦截记录                6. 查看网站拦截记录"
						echo "7. 查看防御规则列表               8. 查看日志实时监控"
						echo "------------------------"
						echo "11. 配置拦截参数"
						echo "------------------------"
						echo "21. cloudflare模式"
						echo "------------------------"
						echo "9. 卸载防御程序"
						echo "------------------------"
						echo "0. 退出"
						echo "------------------------"
						read -p "请输入你的选择: " sub_choice
						case $sub_choice in
						1)
							sed -i 's/false/true/g' /path/to/fail2ban/config/fail2ban/jail.d/alpine-ssh.conf
							sed -i 's/false/true/g' /path/to/fail2ban/config/fail2ban/jail.d/linux-ssh.conf
							sed -i 's/false/true/g' /path/to/fail2ban/config/fail2ban/jail.d/centos-ssh.conf
							f2b_status
							;;
						2)
							sed -i 's/true/false/g' /path/to/fail2ban/config/fail2ban/jail.d/alpine-ssh.conf
							sed -i 's/true/false/g' /path/to/fail2ban/config/fail2ban/jail.d/linux-ssh.conf
							sed -i 's/true/false/g' /path/to/fail2ban/config/fail2ban/jail.d/centos-ssh.conf
							f2b_status
							;;
						3)
							sed -i 's/false/true/g' /path/to/fail2ban/config/fail2ban/jail.d/nginx-docker-cc.conf
							f2b_status
							;;
						4)
							sed -i 's/true/false/g' /path/to/fail2ban/config/fail2ban/jail.d/nginx-docker-cc.conf
							f2b_status
							;;
						5)
							echo "------------------------"
							f2b_sshd
							echo "------------------------"
							;;
						6)

							echo "------------------------"
							xxx=fail2ban-nginx-cc
							f2b_status_xxx
							echo "------------------------"
							xxx=docker-nginx-bad-request
							f2b_status_xxx
							echo "------------------------"
							xxx=docker-nginx-botsearch
							f2b_status_xxx
							echo "------------------------"
							xxx=docker-nginx-http-auth
							f2b_status_xxx
							echo "------------------------"
							xxx=docker-nginx-limit-req
							f2b_status_xxx
							echo "------------------------"
							xxx=docker-php-url-fopen
							f2b_status_xxx
							echo "------------------------"
							;;

						7)
							docker exec -it fail2ban fail2ban-client status
							;;
						8)
							tail -f /path/to/fail2ban/config/log/fail2ban/fail2ban.log

							;;
						9)
							docker rm -f fail2ban
							rm -rf /path/to/fail2ban
							echo "Fail2Ban防御程序已卸载"
							break
							;;

						11)
							install nano
							nano /path/to/fail2ban/config/fail2ban/jail.d/nginx-docker-cc.conf
							f2b_status

							break
							;;
						21)
							echo "到cf后台右上角我的个人资料，选择左侧API令牌，获取Global API Key"
							echo "https://dash.cloudflare.com/login"
							read -p "输入CF的账号: " cfuser
							read -p "输入CF的Global API Key: " cftoken

							wget -O /home/web/conf.d/default.confhttps://raw.githubusercontent.com/kyrxie/tools/main/nginx/default11.conf
							docker restart nginx

							cd /path/to/fail2ban/config/fail2ban/jail.d/
							curl -sS -O https://raw.githubusercontent.com/kyrxie/tools/main/fail2ban/nginx-docker-cc.conf

							cd /path/to/fail2ban/config/fail2ban/action.d
							curl -sS -O https://raw.githubusercontent.com/kyrxie/tools/main/fail2ban/cloudflare-docker.conf

							sed -i "s/kejilion@outlook.com/$cfuser/g" /path/to/fail2ban/config/fail2ban/action.d/cloudflare-docker.conf
							sed -i "s/APIKEY00000/$cftoken/g" /path/to/fail2ban/config/fail2ban/action.d/cloudflare-docker.conf
							f2b_status

							echo "已配置cloudflare模式，可在cf后台，站点-安全性-事件中查看拦截记录"
							;;

						0)
							break
							;;
						*)
							echo "无效的选择，请重新输入。"
							;;
						esac
						break_end

					done

				elif [ -x "$(command -v fail2ban-client)" ]; then
					clear
					echo "卸载旧版fail2ban"
					read -p "确定继续吗？(Y/N): " choice
					case "$choice" in
					[Yy])
						remove fail2ban
						rm -rf /etc/fail2ban
						echo "Fail2Ban防御程序已卸载"
						;;
					[Nn])
						echo "已取消"
						;;
					*)
						echo "无效的选择，请输入 Y 或 N。"
						;;
					esac

				else
					clear
					install_docker

					docker rm -f nginx
					wget -O /home/web/nginx.conf https://raw.githubusercontent.com/kyrxie/tools/main/nginx/nginx10.conf
					wget -O /home/web/conf.d/default.confhttps://raw.githubusercontent.com/kyrxie/tools/main/nginx/default10.conf
					default_server_ssl
					docker run -d --name nginx --restart always --network web_default -p 80:80 -p 443:443 -p 443:443/udp -v /home/web/nginx.conf:/etc/nginx/nginx.conf -v /home/web/conf.d:/etc/nginx/conf.d -v /home/web/certs:/etc/nginx/certs -v /home/web/html:/var/www/html -v /home/web/log/nginx:/var/log/nginx nginx:alpine
					docker exec -it nginx chmod -R 777 /var/www/html

					f2b_install_sshd

					cd /path/to/fail2ban/config/fail2ban/filter.d
					curl -sS -O https://raw.githubusercontent.com/kyrxie/tools/main/fail2ban/fail2ban-nginx-cc.conf
					cd /path/to/fail2ban/config/fail2ban/jail.d/
					curl -sS -O https://raw.githubusercontent.com/kyrxie/tools/main/fail2ban/nginx-docker-cc.conf
					sed -i "/cloudflare/d" /path/to/fail2ban/config/fail2ban/jail.d/nginx-docker-cc.conf

					cd ~
					f2b_status

					echo "防御程序已开启"
				fi
				;;

			36)
				while true; do
					clear
					echo "优化LDNMP环境"
					echo "------------------------"
					echo "1. 标准模式              2. 高性能模式 (推荐2H2G以上)"
					echo "------------------------"
					echo "0. 退出"
					echo "------------------------"
					read -p "请输入你的选择: " sub_choice
					case $sub_choice in
					1)
						# nginx调优
						sed -i 's/worker_connections.*/worker_connections 1024;/' /home/web/nginx.conf

						# mysql调优
						#						wget -O /home/custom_mysql_config.cnf https://raw.githubusercontent.com/kejilion/sh/main/custom_mysql_config-1.cnf
						#						docker cp /home/custom_mysql_config.cnf mysql:/etc/mysql/conf.d/
						#						rm -rf /home/custom_mysql_config.cnf

						docker restart nginx
						#						docker restart mysql

						echo "LDNMP环境已设置成 标准模式"
						;;
					2)

						# nginx调优
						sed -i 's/worker_connections.*/worker_connections 10240;/' /home/web/nginx.conf

						#						# php调优
						#						wget -O /home/www.conf https://raw.githubusercontent.com/kejilion/sh/main/www.conf
						#						docker cp /home/www.conf php:/usr/local/etc/php-fpm.d/www.conf
						#						docker cp /home/www.conf php74:/usr/local/etc/php-fpm.d/www.conf
						#						rm -rf /home/www.conf

						# mysql调优
						#						wget -O /home/custom_mysql_config.cnf https://raw.githubusercontent.com/kejilion/sh/main/custom_mysql_config.cnf
						#						docker cp /home/custom_mysql_config.cnf mysql:/etc/mysql/conf.d/
						#						rm -rf /home/custom_mysql_config.cnf

						docker restart nginx
						#						docker restart php
						#						docker restart php74
						docker restart mysql
						echo "LDNMP环境已设置成 高性能模式"
						;;
					0)
						break
						;;
					*)
						echo "无效的选择，请重新输入。"
						;;
					esac
					break_end

				done
				;;

			38)
				root_use
				read -p "$(echo -e "${hong}强烈建议先备份全部网站数据，再卸载LDNMP环境。确定删除所有网站数据吗？(Y/N): ${bai}")" choice
				case "$choice" in
				[Yy])
					docker rm -f nginx php php74 mysql redis
					docker rmi nginx nginx:alpine php:fpm php:fpm-alpine php:7.4.33-fpm php:7.4-fpm-alpine mysql redis redis:alpine
					rm -rf /home/web

					;;
				[Nn]) ;;

				*)
					echo "无效的选择，请输入 Y 或 N。"
					;;
				esac
				;;

			0)
				s1xu
				;;

			*)
				echo "无效的输入!"
				;;
			esac
			break_end

		done
		;;

	9)
		while true; do
			clear
			echo "▶ 面板工具"
			echo "------------------------"
			echo "1. 宝塔面板官方版                       2. aaPanel宝塔国际版"
			echo "3. 1Panel新一代管理面板                 4. NginxProxyManager可视化面板"
			echo "5. AList多存储文件列表程序               6. 哪吒探针VPS监控面板 "
			echo "7. 青龙面板定时任务管理平台               8. UptimeKuma监控工具 "
			echo "9. Memos网页备忘录"
			echo "0. 返回主菜单"
			echo "------------------------"
			read -p "请输入你的选择: " sub_choice

			case $sub_choice in
			1)
				lujing="[ -d "/www/server/panel" ]"
				panelname="宝塔面板"

				gongneng1="bt"
				gongneng1_1=""
				gongneng2="curl -o bt-uninstall.sh http://download.bt.cn/install/bt-uninstall.sh > /dev/null 2>&1 && chmod +x bt-uninstall.sh && ./bt-uninstall.sh"
				gongneng2_1="chmod +x bt-uninstall.sh"
				gongneng2_2="./bt-uninstall.sh"

				panelurl="https://www.bt.cn/new/index.html"

				centos_mingling="wget -O install.sh https://download.bt.cn/install/install_6.0.sh"
				centos_mingling2="sh install.sh ed8484bec"

				ubuntu_mingling="wget -O install.sh https://download.bt.cn/install/install-ubuntu_6.0.sh"
				ubuntu_mingling2="bash install.sh ed8484bec"
				install_panel
				;;

			2)
				lujing='[ -d "/www/server/panel" ]'
				panelname="aapanel"

				gongneng1="bt"
				gongneng1_1=""
				gongneng2="curl -o bt-uninstall.sh http://download.bt.cn/install/bt-uninstall.sh > /dev/null 2>&1 && chmod +x bt-uninstall.sh && ./bt-uninstall.sh"
				gongneng2_1="chmod +x bt-uninstall.sh"
				gongneng2_2="./bt-uninstall.sh"

				panelurl="https://www.aapanel.com/new/index.html"

				centos_mingling="wget -O install.sh http://www.aapanel.com/script/install_6.0_en.sh"
				centos_mingling2="bash install.sh aapanel"

				ubuntu_mingling="wget -O install.sh http://www.aapanel.com/script/install-ubuntu_6.0_en.sh"
				ubuntu_mingling2="bash install.sh aapanel"
				install_panel
				;;

			3)
				lujing="command -v 1pctl &> /dev/null"
				panelname="1Panel"

				gongneng1="1pctl user-info"
				gongneng1_1="1pctl update password"
				gongneng2="1pctl uninstall"
				gongneng2_1=""
				gongneng2_2=""

				panelurl="https://1panel.cn/"

				centos_mingling="curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh"
				centos_mingling2="sh quick_start.sh"

				ubuntu_mingling="curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh"
				ubuntu_mingling2="bash quick_start.sh"
				install_panel
				;;

			4)
				docker_name="npm"
				docker_img="jc21/nginx-proxy-manager:latest"
				docker_port=81
				docker_rum="docker run -d \
                          --name=$docker_name \
                          -p 80:80 \
                          -p 81:$docker_port \
                          -p 443:443 \
                          -v /home/docker/npm/data:/data \
                          -v /home/docker/npm/letsencrypt:/etc/letsencrypt \
                          --restart=always \
                          $docker_img"
				docker_describe="如果您已经安装了其他面板工具或者LDNMP建站环境，建议先卸载，再安装npm！"
				docker_url="官网介绍: https://nginxproxymanager.com/"
				docker_use="echo \"初始用户名: admin@example.com\""
				docker_passwd="echo \"初始密码: changeme\""
				docker_app
				;;

			5)
				docker_name="alist"
				docker_img="xhofe/alist:latest"
				docker_port=5244
				docker_rum="docker run -d \
                                --restart=always \
                                -v /home/docker/alist:/opt/alist/data \
                                -p 5244:5244 \
                                -e PUID=0 \
                                -e PGID=0 \
                                -e UMASK=022 \
                                --name alist \
                                xhofe/alist:latest"
				docker_describe="一个支持多种存储，支持网页浏览和 WebDAV 的文件列表程序，由 gin 和 Solidjs 驱动"
				docker_url="官网介绍: https://alist.nn.ci/zh/"
				docker_use="docker exec -it alist ./alist admin random"
				docker_passwd=""
				docker_app
				;;

			6)
				clear
				curl -L https://raw.githubusercontent.com/naiba/nezha/master/script/install.sh -o nezha.sh && chmod +x nezha.sh
				./nezha.sh
				;;
			7)
				docker_name="qinglong"
				docker_img="whyour/qinglong:latest"
				docker_port=5700
				docker_rum="docker run -d \
                      -v /home/docker/qinglong/data:/ql/data \
                      -p 5700:5700 \
                      --name qinglong \
                      --hostname qinglong \
                      --restart unless-stopped \
                      whyour/qinglong:latest"
				docker_describe="青龙面板是一个定时任务管理平台"
				docker_url="官网介绍: https://github.com/whyour/qinglong"
				docker_use=""
				docker_passwd=""
				docker_app
				;;

			8)
				docker_name="uptime-kuma"
				docker_img="louislam/uptime-kuma:latest"
				docker_port=3003
				docker_rum="docker run -d \
                            --name=uptime-kuma \
                            -p 3003:3001 \
                            -v /home/docker/uptime-kuma/uptime-kuma-data:/app/data \
                            --restart=always \
                            louislam/uptime-kuma:latest"
				docker_describe="Uptime Kuma 易于使用的自托管监控工具"
				docker_url="官网介绍: https://github.com/louislam/uptime-kuma"
				docker_use=""
				docker_passwd=""
				docker_app
				;;

			9)
				docker_name="memos"
				docker_img="ghcr.io/usememos/memos:latest"
				docker_port=5230
				docker_rum="docker run -d --name memos -p 5230:5230 -v /home/docker/memos:/var/opt/memos --restart always ghcr.io/usememos/memos:latest"
				docker_describe="Memos是一款轻量级、自托管的备忘录中心"
				docker_url="官网介绍: https://github.com/usememos/memos"
				docker_use=""
				docker_passwd=""
				docker_app
				;;

			0)
				s1xu
				;;
			*)
				echo "无效的输入!"
				;;
			esac
			break_end

		done
		;;

	11)
		while true; do
			clear
			echo "▶ 我的工作区"
			echo "系统将为你提供可以后台常驻运行的工作区，你可以用来执行长时间的任务"
			echo "即使你断开SSH，工作区中的任务也不会中断，后台常驻任务。"
			echo -e "${huang}注意: 进入工作区后使用Ctrl+b再单独按d，退出工作区！${bai}"
			echo "------------------------"
			echo "1. 1号工作区"
			echo "2. 2号工作区"
			echo "3. 3号工作区"
			echo "4. 4号工作区"
			echo "5. 5号工作区"
			echo "6. 6号工作区"
			echo "7. 7号工作区"
			echo "8. 8号工作区"
			echo "9. 9号工作区"
			echo "10. 10号工作区"
			echo "11. 自定义工作区"
			echo "------------------------"
			echo "99. 工作区状态管理"
			echo "------------------------"
			echo "0. 返回主菜单"
			echo "------------------------"
			read -p "请输入你的选择: " sub_choice

			case $sub_choice in

			1)
				clear
				install tmux
				SESSION_NAME="work1"
				tmux_run

				;;
			2)
				clear
				install tmux
				SESSION_NAME="work2"
				tmux_run
				;;
			3)
				clear
				install tmux
				SESSION_NAME="work3"
				tmux_run
				;;
			4)
				clear
				install tmux
				SESSION_NAME="work4"
				tmux_run
				;;
			5)
				clear
				install tmux
				SESSION_NAME="work5"
				tmux_run
				;;
			6)
				clear
				install tmux
				SESSION_NAME="work6"
				tmux_run
				;;
			7)
				clear
				install tmux
				SESSION_NAME="work7"
				tmux_run
				;;
			8)
				clear
				install tmux
				SESSION_NAME="work8"
				tmux_run
				;;
			9)
				clear
				install tmux
				SESSION_NAME="work9"
				tmux_run
				;;
			10)
				clear
				install tmux
				SESSION_NAME="work10"
				tmux_run
				;;

			11)
				clear
				install tmux
				clear
				echo "当前已存在的工作区列表"
				echo "------------------------"
				tmux list-sessions
				echo "------------------------"
				read -p "请输入您自定义的工作区名称，如1001 kj001 work10: " SESSION_NAME
				tmux_run
				;;

			99)
				while true; do
					clear
					echo "当前已存在的工作区列表"
					echo "------------------------"
					tmux list-sessions
					echo "------------------------"

					read -p "1. 删除指定工作区    0. 退出: " gongzuoqu_del
					case "$gongzuoqu_del" in
					1)
						read -p "请输入要删除的工作区名称: " gongzuoqu_name
						tmux kill-window -t $gongzuoqu_name
						;;
					0)
						break
						;;
					*)
						echo "无效的选择，请输入 Y 或 N。"
						;;
					esac
				done
				;;
			0)
				s1xu
				;;
			*)
				echo "无效的输入!"
				;;
			esac
			break_end

		done
		;;

	12)
		while true; do
			clear
			echo "▶ 系统工具"
			echo "------------------------"
			echo "1. 设置脚本启动快捷键                  2. 修改登录密码"
			echo "3. ROOT密码登录模式                    4. 安装Python最新版"
			echo "5. 开放所有端口                        6. 修改SSH连接端口"
			echo "7. 优化DNS地址                         8. 一键重装系统"
			echo "9. 创建新账户 禁用ROOT                  10. 切换优先ipv4/ipv6"
			echo "------------------------"
			echo "11. 查看端口占用状态                   12. 修改虚拟内存大小"
			echo "13. 用户管理                           14. 用户/密码生成器"
			echo "15. 系统时区调整                      			"
			echo "17. 防火墙高级管理器                   18. 修改主机名"
			echo "19. 切换系统更新源                     20. 定时任务管理"
			echo "------------------------"
			echo "21. 本机host解析                       22. fail2banSSH防御程序"
			echo "23. 限流自动关机                       24. ROOT私钥登录模式"
			echo "------------------------"
			echo "66. 一条龙系统调优"
			echo "------------------------"
			echo "99. 重启服务器"
			echo "------------------------"
			echo "0. 返回主菜单"
			echo "------------------------"
			read -p "请输入你的选择: " sub_choice

			case $sub_choice in
			1)
				clear
				read -p "请输入你的快捷按键: " kuaijiejian
				echo "alias $kuaijiejian='~/s1xutools.sh'" >>~/.bashrc
				source ~/.bashrc
				echo "快捷键已设置"
				;;

			2)
				clear
				echo "设置你的登录密码"
				passwd
				;;
			3)
				root_use
				add_sshpasswd
				;;

			4)
				root_use

				# 系统检测
				OS=$(cat /etc/os-release | grep -o -E "Debian|Ubuntu|CentOS" | head -n 1)

				if [[ $OS == "Debian" || $OS == "Ubuntu" || $OS == "CentOS" ]]; then
					echo -e "检测到你的系统是 ${huang}${OS}${bai}"
				else
					echo -e "${hong}很抱歉，你的系统不受支持！${bai}"
					exit 1
				fi

				# 检测安装Python3的版本
				VERSION=$(python3 -V 2>&1 | awk '{print $2}')

				# 获取最新Python3版本
				PY_VERSION=$(curl -s https://www.python.org/ | grep "downloads/release" | grep -o 'Python [0-9.]*' | grep -o '[0-9.]*')

				# 卸载Python3旧版本
				if [[ $VERSION == "3"* ]]; then
					echo -e "${huang}你的Python3版本是${bai}${hong}${VERSION}${bai}，${huang}最新版本是${bai}${hong}${PY_VERSION}${bai}"
					read -p "是否确认升级最新版Python3？默认不升级 [y/N]: " CONFIRM
					if [[ $CONFIRM == "y" ]]; then
						if [[ $OS == "CentOS" ]]; then
							echo ""
							rm-rf /usr/local/python3* >/dev/null 2>&1
						else
							apt --purge remove python3 python3-pip -y
							rm-rf /usr/local/python3*
						fi
					else
						echo -e "${huang}已取消升级Python3${bai}"
						exit 1
					fi
				else
					echo -e "${hong}检测到没有安装Python3。${bai}"
					read -p "是否确认安装最新版Python3？默认安装 [Y/n]: " CONFIRM
					if [[ $CONFIRM != "n" ]]; then
						echo -e "${lv}开始安装最新版Python3...${bai}"
					else
						echo -e "${huang}已取消安装Python3${bai}"
						exit 1
					fi
				fi

				# 安装相关依赖
				if [[ $OS == "CentOS" ]]; then
					yum update
					yum groupinstall -y "development tools"
					yum install wget openssl-devel bzip2-devel libffi-devel zlib-devel -y
				else
					apt update
					apt install wget build-essential libreadline-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev -y
				fi

				# 安装python3
				cd /root/
				wget https://www.python.org/ftp/python/${PY_VERSION}/Python-"$PY_VERSION".tgz
				tar -zxf Python-${PY_VERSION}.tgz
				cd Python-${PY_VERSION}
				./configure --prefix=/usr/local/python3
				make -j $(nproc)
				make install
				if [ $? -eq 0 ]; then
					rm -f /usr/local/bin/python3*
					rm -f /usr/local/bin/pip3*
					ln -sf /usr/local/python3/bin/python3 /usr/bin/python3
					ln -sf /usr/local/python3/bin/pip3 /usr/bin/pip3
					clear
					echo -e "${huang}Python3安装${lv}成功，${bai}版本为: ${bai}${lv}${PY_VERSION}${bai}"
				else
					clear
					echo -e "${hong}Python3安装失败！${bai}"
					exit 1
				fi
				cd /root/ && rm -rf Python-${PY_VERSION}.tgz && rm -rf Python-${PY_VERSION}
				;;

			5)
				root_use
				iptables_open
				remove iptables-persistent ufw firewalld iptables-services >/dev/null 2>&1
				echo "端口已全部开放"
				;;
			6)
				root_use
				# 去掉 #Port 的注释
				sed -i 's/#Port/Port/' /etc/ssh/sshd_config

				# 读取当前的 SSH 端口号
				current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

				# 打印当前的 SSH 端口号
				echo "当前的 SSH 端口号是: $current_port"

				echo "------------------------"

				# 提示用户输入新的 SSH 端口号
				read -p "请输入新的 SSH 端口号: " new_port

				new_ssh_port
				;;

			7)
				root_use
				echo "当前DNS地址"
				echo "------------------------"
				cat /etc/resolv.conf
				echo "------------------------"
				echo ""
				# 询问用户是否要优化DNS设置
				read -p "是否要设置DNS地址？(y/n): " choice

				if [ "$choice" == "y" ]; then
					read -p "1. 国外DNS优化    2. 国内DNS优化    0. 退出  : " Limiting

					case "$Limiting" in
					1)

						dns1_ipv4="1.1.1.1"
						dns2_ipv4="8.8.8.8"
						dns1_ipv6="2606:4700:4700::1111"
						dns2_ipv6="2001:4860:4860::8888"
						set_dns
						;;

					2)
						dns1_ipv4="223.5.5.5"
						dns2_ipv4="183.60.83.19"
						dns1_ipv6="2400:3200::1"
						dns2_ipv6="2400:da00::6666"
						set_dns
						;;
					0)
						echo "已取消"
						;;
					*)
						echo "无效的选择，请输入 Y 或 N。"
						;;
					esac

				else
					echo "DNS设置未更改"
				fi
				;;

			8)

				dd_xitong_1() {
					echo -e "重装后初始用户名: ${huang}root${bai}  初始密码: ${huang}LeitboGi0ro${bai}  初始端口: ${huang}22${bai}"
					echo -e "按任意键继续..."
					read -n 1 -s -r -p ""
					install wget
					wget --no-check-certificate -qO InstallNET.sh 'https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh' && chmod a+x InstallNET.sh
				}

				dd_xitong_2() {
					echo -e "重装后初始用户名: ${huang}Administrator${bai}  初始密码: ${huang}Teddysun.com${bai}  初始端口: ${huang}3389${bai}"
					echo -e "按任意键继续..."
					read -n 1 -s -r -p ""
					install wget
					wget --no-check-certificate -qO InstallNET.sh 'https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh' && chmod a+x InstallNET.sh
				}

				dd_xitong_3() {
					echo -e "重装后初始用户名: ${huang}root${bai}  初始密码: ${huang}123@@@${bai}  初始端口: ${huang}22${bai}"
					echo -e "按任意键继续..."
					read -n 1 -s -r -p ""
					curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh
				}

				dd_xitong_4() {
					echo -e "重装后初始用户名: ${huang}Administrator${bai}  初始密码: ${huang}123@@@${bai}  初始端口: ${huang}3389${bai}"
					echo -e "按任意键继续..."
					read -n 1 -s -r -p ""
					curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh
				}

				while true; do
					root_use
					echo "请备份数据，将为你重装系统，预计花费15分钟。"
					echo -e "${hui}感谢MollyLau大佬和bin456789大佬的脚本支持！${bai} "
					echo "------------------------"
					echo "1. Debian 12"
					echo "2. Debian 11"
					echo "3. Debian 10"
					echo "4. Debian 9"
					echo "------------------------"
					echo "11. Ubuntu 24.04"
					echo "12. Ubuntu 22.04"
					echo "13. Ubuntu 20.04"
					echo "14. Ubuntu 18.04"
					echo "------------------------"
					echo "21. CentOS 9"
					echo "22. CentOS 8"
					echo "23. CentOS 7"
					echo "------------------------"
					echo "31. Alpine Linux"
					echo "------------------------"
					echo "41. Windows 11"
					echo "42. Windows 10"
					echo "43. Windows 7"
					echo "44. Windows Server 2022"
					echo "45. Windows Server 2019"
					echo "46. Windows Server 2016"
					echo "------------------------"
					echo "0. 返回上一级选单"
					echo "------------------------"
					read -p "请选择要重装的系统: " sys_choice

					case "$sys_choice" in
					1)
						dd_xitong_1
						bash InstallNET.sh -debian 12
						reboot
						exit
						;;

					2)
						dd_xitong_1
						bash InstallNET.sh -debian 11
						reboot
						exit
						;;

					3)
						dd_xitong_1
						bash InstallNET.sh -debian 10
						reboot
						exit
						;;
					4)
						dd_xitong_1
						bash InstallNET.sh -debian 9
						reboot
						exit
						;;

					11)
						dd_xitong_1
						bash InstallNET.sh -ubuntu 24.04
						reboot
						exit
						;;
					12)
						dd_xitong_1
						bash InstallNET.sh -ubuntu 22.04
						reboot
						exit
						;;

					13)
						dd_xitong_1
						bash InstallNET.sh -ubuntu 20.04
						reboot
						exit
						;;
					14)
						dd_xitong_1
						bash InstallNET.sh -ubuntu 18.04
						reboot
						exit
						;;

					21)
						dd_xitong_1
						bash InstallNET.sh -centos 9
						reboot
						exit
						;;

					22)
						dd_xitong_1
						bash InstallNET.sh -centos 8
						reboot
						exit
						;;

					23)
						dd_xitong_1
						bash InstallNET.sh -centos 7
						reboot
						exit
						;;

					31)
						dd_xitong_1
						bash InstallNET.sh -alpine
						reboot
						exit
						;;

					41)
						dd_xitong_2
						bash InstallNET.sh -windows 11 -lang "cn"
						reboot
						exit
						;;

					42)
						dd_xitong_2
						bash InstallNET.sh -windows 10 -lang "cn"
						reboot
						exit
						;;

					43)
						dd_xitong_4
						URL="https://massgrave.dev/windows_7_links"
						web_content=$(wget -q -O - "$URL")
						iso_link=$(echo "$web_content" | grep -oP '(?<=href=")[^"]*cn[^"]*windows_7[^"]*professional[^"]*x64[^"]*\.iso')
						# bash reinstall.sh windows --image-name 'Windows 7 Professional' --lang zh-cn
						# bash reinstall.sh windows --iso='$iso_link' --image-name='Windows 7 PROFESSIONAL'
						bash reinstall.sh windows --iso="$iso_link" --image-name='Windows 7 PROFESSIONAL'

						reboot
						exit
						;;

					44)
						dd_xitong_4
						URL="https://massgrave.dev/windows_server_links"
						web_content=$(wget -q -O - "$URL")
						iso_link=$(echo "$web_content" | grep -oP '(?<=href=")[^"]*cn[^"]*windows_server[^"]*2022[^"]*x64[^"]*\.iso')
						bash reinstall.sh windows --iso="$iso_link" --image-name='Windows Server 2022 SERVERDATACENTER'
						reboot
						exit
						;;

					45)
						dd_xitong_2
						bash InstallNET.sh -windows 2019 -lang "cn"
						reboot
						exit
						;;

					46)
						dd_xitong_2
						bash InstallNET.sh -windows 2016 -lang "cn"
						reboot
						exit
						;;

					0)
						break
						;;

					*)
						echo "无效的选择，请重新输入。"
						break
						;;
					esac
				done
				;;
			9)
				root_use

				read -p "请输入新用户名: " new_username

				useradd -m -s /bin/bash "$new_username"
				passwd "$new_username"

				# 赋予新用户sudo权限
				echo "$new_username ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers

				# 禁用ROOT用户登录
				passwd -l root

				echo "操作已完成。"
				;;

			10)
				root_use
				ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6)

				echo ""
				if [ "$ipv6_disabled" -eq 1 ]; then
					echo "当前网络优先级设置: IPv4 优先"
				else
					echo "当前网络优先级设置: IPv6 优先"
				fi
				echo "------------------------"

				echo ""
				echo "切换的网络优先级"
				echo "------------------------"
				echo "1. IPv4 优先          2. IPv6 优先"
				echo "------------------------"
				read -p "选择优先的网络: " choice

				case $choice in
				1)
					sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
					echo "已切换为 IPv4 优先"
					;;
				2)
					sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
					echo "已切换为 IPv6 优先"
					;;
				*)
					echo "无效的选择"
					;;
				esac
				;;

			11)
				clear
				ss -tulnape
				;;

			12)
				root_use
				# 获取当前交换空间信息
				swap_used=$(free -m | awk 'NR==3{print $3}')
				swap_total=$(free -m | awk 'NR==3{print $2}')

				if [ "$swap_total" -eq 0 ]; then
					swap_percentage=0
				else
					swap_percentage=$((swap_used * 100 / swap_total))
				fi

				swap_info="${swap_used}MB/${swap_total}MB (${swap_percentage}%)"

				echo "当前虚拟内存: $swap_info"

				read -p "是否调整大小?(Y/N): " choice

				case "$choice" in
				[Yy])
					# 输入新的虚拟内存大小
					read -p "请输入虚拟内存大小MB: " new_swap
					add_swap

					;;
				[Nn])
					echo "已取消"
					;;
				*)
					echo "无效的选择，请输入 Y 或 N。"
					;;
				esac
				;;

			13)
				while true; do
					root_use

					echo "用户列表"
					echo "----------------------------------------------------------------------------"
					printf "%-24s %-34s %-20s %-10s\n" "用户名" "用户权限" "用户组" "sudo权限"
					while IFS=: read -r username _ userid groupid _ _ homedir shell; do
						groups=$(groups "$username" | cut -d : -f 2)
						sudo_status=$(sudo -n -lU "$username" 2>/dev/null | grep -q '(ALL : ALL)' && echo "Yes" || echo "No")
						printf "%-20s %-30s %-20s %-10s\n" "$username" "$homedir" "$groups" "$sudo_status"
					done </etc/passwd

					echo ""
					echo "账户操作"
					echo "------------------------"
					echo "1. 创建普通账户             2. 创建高级账户"
					echo "------------------------"
					echo "3. 赋予最高权限             4. 取消最高权限"
					echo "------------------------"
					echo "5. 删除账号"
					echo "------------------------"
					echo "0. 返回上一级选单"
					echo "------------------------"
					read -p "请输入你的选择: " sub_choice

					case $sub_choice in
					1)
						read -p "请输入新用户名: " new_username

						useradd -m -s /bin/bash "$new_username"
						passwd "$new_username"

						echo "操作已完成。"
						;;

					2)
						# 提示用户输入新用户名
						read -p "请输入新用户名: " new_username

						# 创建新用户并设置密码
						useradd -m -s /bin/bash "$new_username"
						passwd "$new_username"

						# 赋予新用户sudo权限
						echo "$new_username ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers

						echo "操作已完成。"
						;;
					3)
						read -p "请输入用户名: " username
						# 赋予新用户sudo权限
						echo "$username ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers
						;;
					4)
						read -p "请输入用户名: " username
						# 从sudoers文件中移除用户的sudo权限
						sed -i "/^$username\sALL=(ALL:ALL)\sALL/d" /etc/sudoers

						;;
					5)
						read -p "请输入要删除的用户名: " username
						# 删除用户及其主目录
						userdel -r "$username"
						;;

					0)
						break
						;;

					*)
						break
						;;
					esac
				done
				;;

			14)
				clear

				echo "随机用户名"
				echo "------------------------"
				for i in {1..5}; do
					username="user$(tr </dev/urandom -dc _a-z0-9 | head -c6)"
					echo "随机用户名 $i: $username"
				done

				echo ""
				echo "随机姓名"
				echo "------------------------"
				first_names=("John" "Jane" "Michael" "Emily" "David" "Sophia" "William" "Olivia" "James" "Emma" "Ava" "Liam" "Mia" "Noah" "Isabella")
				last_names=("Smith" "Johnson" "Brown" "Davis" "Wilson" "Miller" "Jones" "Garcia" "Martinez" "Williams" "Lee" "Gonzalez" "Rodriguez" "Hernandez")

				# 生成5个随机用户姓名
				for i in {1..5}; do
					first_name_index=$((RANDOM % ${#first_names[@]}))
					last_name_index=$((RANDOM % ${#last_names[@]}))
					user_name="${first_names[$first_name_index]} ${last_names[$last_name_index]}"
					echo "随机用户姓名 $i: $user_name"
				done

				echo ""
				echo "随机UUID"
				echo "------------------------"
				for i in {1..5}; do
					uuid=$(cat /proc/sys/kernel/random/uuid)
					echo "随机UUID $i: $uuid"
				done

				echo ""
				echo "16位随机密码"
				echo "------------------------"
				for i in {1..5}; do
					password=$(tr </dev/urandom -dc _A-Z-a-z-0-9 | head -c16)
					echo "随机密码 $i: $password"
				done

				echo ""
				echo "32位随机密码"
				echo "------------------------"
				for i in {1..5}; do
					password=$(tr </dev/urandom -dc _A-Z-a-z-0-9 | head -c32)
					echo "随机密码 $i: $password"
				done
				echo ""
				;;

			15)
				root_use
				while true; do
					echo "系统时间信息"
					timezone=$(current_timezone)
					current_time=$(date +"%Y-%m-%d %H:%M:%S")

					echo "当前系统时区：$timezone"
					echo "当前系统时间：$current_time"

					echo ""
					echo "时区切换"
					echo "亚洲------------------------"
					echo "1. 中国上海时间              2. 中国香港时间"
					echo "3. 日本东京时间              4. 韩国首尔时间"
					echo "5. 新加坡时间                6. 印度加尔各答时间"
					echo "7. 阿联酋迪拜时间            8. 澳大利亚悉尼时间"
					echo "欧洲------------------------"
					echo "11. 英国伦敦时间             12. 法国巴黎时间"
					echo "13. 德国柏林时间             14. 俄罗斯莫斯科时间"
					echo "15. 荷兰尤特赖赫特时间       16. 西班牙马德里时间"
					echo "美洲------------------------"
					echo "21. 美国西部时间             22. 美国东部时间"
					echo "23. 加拿大时间               24. 墨西哥时间"
					echo "25. 巴西时间                 26. 阿根廷时间"
					echo "------------------------"
					echo "0. 返回上一级选单"
					echo "------------------------"
					read -p "请输入你的选择: " sub_choice

					case $sub_choice in
					1) set_timedate Asia/Shanghai ;;
					2) set_timedate Asia/Hong_Kong ;;
					3) set_timedate Asia/Tokyo ;;
					4) set_timedate Asia/Seoul ;;
					5) set_timedate Asia/Singapore ;;
					6) set_timedate Asia/Kolkata ;;
					7) set_timedate Asia/Dubai ;;
					8) set_timedate Australia/Sydney ;;
					11) set_timedate Europe/London ;;
					12) set_timedate Europe/Paris ;;
					13) set_timedate Europe/Berlin ;;
					14) set_timedate Europe/Moscow ;;
					15) set_timedate Europe/Amsterdam ;;
					16) set_timedate Europe/Madrid ;;
					21) set_timedate America/Los_Angeles ;;
					22) set_timedate America/New_York ;;
					23) set_timedate America/Vancouver ;;
					24) set_timedate America/Mexico_City ;;
					25) set_timedate America/Sao_Paulo ;;
					26) set_timedate America/Argentina/Buenos_Aires ;;
					0) break ;;
					*) break ;;
					esac
				done
				;;

			17)
				root_use
				if dpkg -l | grep -q iptables-persistent; then
					while true; do
						echo "防火墙已安装"
						echo "------------------------"
						iptables -L INPUT

						echo ""
						echo "防火墙管理"
						echo "------------------------"
						echo "1. 开放指定端口              2. 关闭指定端口"
						echo "3. 开放所有端口              4. 关闭所有端口"
						echo "------------------------"
						echo "5. IP白名单                  6. IP黑名单"
						echo "7. 清除指定IP"
						echo "------------------------"
						echo "9. 卸载防火墙"
						echo "------------------------"
						echo "0. 返回上一级选单"
						echo "------------------------"
						read -p "请输入你的选择: " sub_choice

						case $sub_choice in
						1)
							read -p "请输入开放的端口号: " o_port
							sed -i "/COMMIT/i -A INPUT -p tcp --dport $o_port -j ACCEPT" /etc/iptables/rules.v4
							sed -i "/COMMIT/i -A INPUT -p udp --dport $o_port -j ACCEPT" /etc/iptables/rules.v4
							iptables-restore </etc/iptables/rules.v4

							;;
						2)
							read -p "请输入关闭的端口号: " c_port
              sed -i "/--dport $c_port[^0-9]/d" /etc/iptables/rules.v4
              iptables-restore </etc/iptables/rules.v4
							;;

						3)
							current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

							cat >/etc/iptables/rules.v4 <<EOF
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A FORWARD -i lo -j ACCEPT
-A INPUT -p tcp --dport $current_port -j ACCEPT
COMMIT
EOF
							iptables-restore </etc/iptables/rules.v4
							;;
						4)
							current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

							cat >/etc/iptables/rules.v4 <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A FORWARD -i lo -j ACCEPT
-A INPUT -p tcp --dport $current_port -j ACCEPT
COMMIT
EOF
							iptables-restore </etc/iptables/rules.v4
							;;

						5)
							read -p "请输入放行的IP: " o_ip
							sed -i "/COMMIT/i -A INPUT -s $o_ip -j ACCEPT" /etc/iptables/rules.v4
							iptables-restore </etc/iptables/rules.v4
							;;

						6)
							read -p "请输入封锁的IP: " c_ip
							sed -i "/COMMIT/i -A INPUT -s $c_ip -j DROP" /etc/iptables/rules.v4
							iptables-restore </etc/iptables/rules.v4
							;;

						7)
							read -p "请输入清除的IP: " d_ip
							sed -i "/-A INPUT -s $d_ip/d" /etc/iptables/rules.v4
							iptables-restore </etc/iptables/rules.v4
							;;

						9)
							remove iptables-persistent
							rm /etc/iptables/rules.v4
							break
							;;

						0)
							break
							;;

						*)
							break
							;;

						esac
					done
				else

					clear
					echo "将为你安装防火墙，该防火墙仅支持Debian/Ubuntu"
					echo "------------------------------------------------"
					read -p "确定继续吗？(Y/N): " choice

					case "$choice" in
					[Yy])
						if [ -r /etc/os-release ]; then
							. /etc/os-release
							if [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
								echo "当前环境不支持，仅支持Debian和Ubuntu系统"
								break
							fi
						else
							echo "无法确定操作系统类型"
							break
						fi

						clear
						iptables_open
						remove iptables-persistent ufw
						rm /etc/iptables/rules.v4

						apt update -y && apt install -y iptables-persistent

						current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

						cat >/etc/iptables/rules.v4 <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A FORWARD -i lo -j ACCEPT
-A INPUT -p tcp --dport $current_port -j ACCEPT
COMMIT
EOF

						iptables-restore </etc/iptables/rules.v4
						systemctl enable netfilter-persistent
						echo "防火墙安装完成"

						;;

					[Nn])
						echo "已取消"
						;;
					*)
						echo "无效的选择，请输入 Y 或 N。"
						;;
					esac
				fi
				;;

			18)
				root_use
				current_hostname=$(hostname)
				echo "当前主机名: $current_hostname"
				read -p "是否要更改主机名？(y/n): " answer
				if [[ "${answer,,}" == "y" ]]; then
					# 获取新的主机名
					read -p "请输入新的主机名: " new_hostname
					if [ -n "$new_hostname" ]; then
						if [ -f /etc/alpine-release ]; then
							# Alpine
							echo "$new_hostname" >/etc/hostname
							hostname "$new_hostname"
						else
							# 其他系统，如 Debian, Ubuntu, CentOS 等
							hostnamectl set-hostname "$new_hostname"
							sed -i "s/$current_hostname/$new_hostname/g" /etc/hostname
							systemctl restart systemd-hostnamed
						fi
						echo "主机名已更改为: $new_hostname"
					else
						echo "无效的主机名。未更改主机名。"
						exit 1
					fi
				else
					echo "未更改主机名。"
				fi
				;;

			19)
				root_use
				# 获取系统信息
				source /etc/os-release

				# 定义 Ubuntu 更新源
				aliyun_ubuntu_source="http://mirrors.aliyun.com/ubuntu/"
				official_ubuntu_source="http://archive.ubuntu.com/ubuntu/"
				initial_ubuntu_source=""

				# 定义 Debian 更新源
				aliyun_debian_source="http://mirrors.aliyun.com/debian/"
				official_debian_source="http://deb.debian.org/debian/"
				initial_debian_source=""

				# 定义 CentOS 更新源
				aliyun_centos_source="http://mirrors.aliyun.com/centos/"
				official_centos_source="http://mirror.centos.org/centos/"
				initial_centos_source=""

				# 获取当前更新源并设置初始源
				case "$ID" in
				ubuntu)
					initial_ubuntu_source=$(grep -E '^deb ' /etc/apt/sources.list | head -n 1 | awk '{print $2}')
					;;
				debian)
					initial_debian_source=$(grep -E '^deb ' /etc/apt/sources.list | head -n 1 | awk '{print $2}')
					;;
				centos)
					initial_centos_source=$(awk -F= '/^baseurl=/ {print $2}' /etc/yum.repos.d/CentOS-Base.repo | head -n 1 | tr -d ' ')
					;;
				*)
					echo "未知系统，无法执行切换源脚本"
					exit 1
					;;
				esac

				# 备份当前源
				backup_sources() {
					case "$ID" in
					ubuntu)
						cp /etc/apt/sources.list /etc/apt/sources.list.bak
						;;
					debian)
						cp /etc/apt/sources.list /etc/apt/sources.list.bak
						;;
					centos)
						if [ ! -f /etc/yum.repos.d/CentOS-Base.repo.bak ]; then
							cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
						else
							echo "备份已存在，无需重复备份"
						fi
						;;
					*)
						echo "未知系统，无法执行备份操作"
						exit 1
						;;
					esac
					echo "已备份当前更新源为 /etc/apt/sources.list.bak 或 /etc/yum.repos.d/CentOS-Base.repo.bak"
				}

				# 还原初始更新源
				restore_initial_source() {
					case "$ID" in
					ubuntu)
						cp /etc/apt/sources.list.bak /etc/apt/sources.list
						;;
					debian)
						cp /etc/apt/sources.list.bak /etc/apt/sources.list
						;;
					centos)
						cp /etc/yum.repos.d/CentOS-Base.repo.bak /etc/yum.repos.d/CentOS-Base.repo
						;;
					*)
						echo "未知系统，无法执行还原操作"
						exit 1
						;;
					esac
					echo "已还原初始更新源"
				}

				# 函数：切换更新源
				switch_source() {
					case "$ID" in
					ubuntu)
						sed -i 's|'"$initial_ubuntu_source"'|'"$1"'|g' /etc/apt/sources.list
						;;
					debian)
						sed -i 's|'"$initial_debian_source"'|'"$1"'|g' /etc/apt/sources.list
						;;
					centos)
						sed -i "s|^baseurl=.*$|baseurl=$1|g" /etc/yum.repos.d/CentOS-Base.repo
						;;
					*)
						echo "未知系统，无法执行切换操作"
						exit 1
						;;
					esac
				}

				# 主菜单
				while true; do
					case "$ID" in
					ubuntu)
						echo "Ubuntu 更新源切换脚本"
						echo "------------------------"
						;;
					debian)
						echo "Debian 更新源切换脚本"
						echo "------------------------"
						;;
					centos)
						echo "CentOS 更新源切换脚本"
						echo "------------------------"
						;;
					*)
						echo "未知系统，无法执行脚本"
						exit 1
						;;
					esac

					echo "1. 切换到阿里云源"
					echo "2. 切换到官方源"
					echo "------------------------"
					echo "3. 备份当前更新源"
					echo "4. 还原初始更新源"
					echo "------------------------"
					echo "0. 返回上一级"
					echo "------------------------"
					read -p "请选择操作: " choice

					case $choice in
					1)
						backup_sources
						case "$ID" in
						ubuntu)
							switch_source $aliyun_ubuntu_source
							;;
						debian)
							switch_source $aliyun_debian_source
							;;
						centos)
							switch_source $aliyun_centos_source
							;;
						*)
							echo "未知系统，无法执行切换操作"
							exit 1
							;;
						esac
						echo "已切换到阿里云源"
						;;
					2)
						backup_sources
						case "$ID" in
						ubuntu)
							switch_source $official_ubuntu_source
							;;
						debian)
							switch_source $official_debian_source
							;;
						centos)
							switch_source $official_centos_source
							;;
						*)
							echo "未知系统，无法执行切换操作"
							exit 1
							;;
						esac
						echo "已切换到官方源"
						;;
					3)
						backup_sources
						case "$ID" in
						ubuntu)
							switch_source $initial_ubuntu_source
							;;
						debian)
							switch_source $initial_debian_source
							;;
						centos)
							switch_source $initial_centos_source
							;;
						*)
							echo "未知系统，无法执行切换操作"
							exit 1
							;;
						esac
						echo "已切换到初始更新源"
						;;
					4)
						restore_initial_source
						;;
					0)
						break
						;;
					*)
						echo "无效的选择，请重新输入"
						;;
					esac
					break_end
				done
				;;

			20)
				while true; do
					clear
					echo "定时任务列表"
					crontab -l
					echo ""
					echo "操作"
					echo "------------------------"
					echo "1. 添加定时任务              2. 删除定时任务              3. 编辑定时任务"
					echo "------------------------"
					echo "0. 返回上一级选单"
					echo "------------------------"
					read -p "请输入你的选择: " sub_choice

					case $sub_choice in
					1)
						read -p "请输入新任务的执行命令: " newquest
						echo "------------------------"
						echo "1. 每月任务                 2. 每周任务"
						echo "3. 每天任务                 4. 每小时任务"
						echo "------------------------"
						read -p "请输入你的选择: " dingshi

						case $dingshi in
						1)
							read -p "选择每月的几号执行任务？ (1-30): " day
							(
								crontab -l
								echo "0 0 $day * * $newquest"
							) | crontab - >/dev/null 2>&1
							;;
						2)
							read -p "选择周几执行任务？ (0-6，0代表星期日): " weekday
							(
								crontab -l
								echo "0 0 * * $weekday $newquest"
							) | crontab - >/dev/null 2>&1
							;;
						3)
							read -p "选择每天几点执行任务？（小时，0-23）: " hour
							(
								crontab -l
								echo "0 $hour * * * $newquest"
							) | crontab - >/dev/null 2>&1
							;;
						4)
							read -p "输入每小时的第几分钟执行任务？（分钟，0-60）: " minute
							(
								crontab -l
								echo "$minute * * * * $newquest"
							) | crontab - >/dev/null 2>&1
							;;
						*)
							break # 跳出
							;;
						esac
						;;
					2)
						read -p "请输入需要删除任务的关键字: " kquest
						crontab -l | grep -v "$kquest" | crontab -
						;;
					3)
						crontab -e
						;;
					0)
						break
						;;

					*)
						break
						;;
					esac
				done
				;;

			21)
				root_use
				while true; do
					echo "本机host解析列表"
					echo "如果你在这里添加解析匹配，将不再使用动态解析了"
					cat /etc/hosts
					echo ""
					echo "操作"
					echo "------------------------"
					echo "1. 添加新的解析              2. 删除解析地址"
					echo "------------------------"
					echo "0. 返回上一级选单"
					echo "------------------------"
					read -p "请输入你的选择: " host_dns

					case $host_dns in
					1)
						read -p "请输入新的解析记录 格式: 110.25.5.33 x.pro : " addhost
						echo "$addhost" >>/etc/hosts

						;;
					2)
						read -p "请输入需要删除的解析内容关键字: " delhost
						sed -i "/$delhost/d" /etc/hosts
						;;
					0)
						break
						;;

					*)
						break
						;;
					esac
				done
				;;

			22)
				root_use
				if docker inspect fail2ban &>/dev/null; then
					while true; do
						clear
						echo "SSH防御程序已启动"
						echo "------------------------"
						echo "1. 查看SSH拦截记录"
						echo "2. 日志实时监控"
						echo "------------------------"
						echo "9. 卸载防御程序"
						echo "------------------------"
						echo "0. 退出"
						echo "------------------------"
						read -p "请输入你的选择: " sub_choice
						case $sub_choice in

						1)
							echo "------------------------"
							f2b_sshd
							echo "------------------------"
							;;
						2)
							tail -f /path/to/fail2ban/config/log/fail2ban/fail2ban.log
							break
							;;
						9)
							docker rm -f fail2ban
							rm -rf /path/to/fail2ban
							echo "Fail2Ban防御程序已卸载"

							break
							;;
						0)
							break
							;;
						*)
							echo "无效的选择，请重新输入。"
							;;
						esac
						break_end
					done

				elif [ -x "$(command -v fail2ban-client)" ]; then
					clear
					echo "卸载旧版fail2ban"
					read -p "确定继续吗？(Y/N): " choice
					case "$choice" in
					[Yy])
						remove fail2ban
						rm -rf /etc/fail2ban
						echo "Fail2Ban防御程序已卸载"
						;;
					[Nn])
						echo "已取消"
						;;
					*)
						echo "无效的选择，请输入 Y 或 N。"
						;;
					esac

				else
					clear
					echo "fail2ban是一个SSH防止暴力破解工具"
					echo "官网介绍: https://github.com/fail2ban/fail2ban"
					echo "------------------------------------------------"
					echo "工作原理：研判非法IP恶意高频访问SSH端口，自动进行IP封锁"
					echo "------------------------------------------------"
					read -p "确定继续吗？(Y/N): " choice

					case "$choice" in
					[Yy])
						clear
						install_docker
						f2b_install_sshd

						cd ~
						f2b_status
						echo "Fail2Ban防御程序已开启"

						;;
					[Nn])
						echo "已取消"
						;;
					*)
						echo "无效的选择，请输入 Y 或 N。"
						;;
					esac
				fi
				;;

			23)
				root_use
				echo "当前流量使用情况，重启服务器流量计算会清零！"
				output_status
				echo "$output"

				# 检查是否存在 Limiting_Shut_down.sh 文件
				if [ -f ~/Limiting_Shut_down.sh ]; then
					# 获取 threshold_gb 的值
					threshold_gb=$(grep -oP 'threshold_gb=\K\d+' ~/Limiting_Shut_down.sh)
					echo -e "当前设置的限流阈值为 ${hang}${threshold_gb}${bai}GB"
				else
					echo -e "${hui}前未启用限流关机功能${bai}"
				fi

				echo
				echo "------------------------------------------------"
				echo "系统每分钟会检测实际流量是否到达阈值，到达后会自动关闭服务器！每月1日重置流量重启服务器。"
				read -p "1. 开启限流关机功能    2. 停用限流关机功能    0. 退出  : " Limiting

				case "$Limiting" in
				1)
					# 输入新的虚拟内存大小
					echo "如果实际服务器就100G流量，可设置阈值为95G，提前关机，以免出现流量误差或溢出."
					read -p "请输入流量阈值（单位为GB）: " threshold_gb
					cd ~
					curl -Ss -O https://raw.githubusercontent.com/kyrxie/tools/main/scripts/limiting_Shut_down.sh
					chmod +x ~/limiting_Shut_down.sh
					sed -i "s/110/$threshold_gb/g" ~/limiting_Shut_down.sh
					crontab -l | grep -v '~/Limiting_Shut_down.sh' | crontab -
					(
						crontab -l
						echo "* * * * * ~/Limiting_Shut_down.sh"
					) | crontab - >/dev/null 2>&1
					crontab -l | grep -v 'reboot' | crontab -
					(
						crontab -l
						echo "0 1 1 * * reboot"
					) | crontab - >/dev/null 2>&1
					echo "限流关机已设置"

					;;
				0)
					echo "已取消"
					;;
				2)
					crontab -l | grep -v '~/Limiting_Shut_down.sh' | crontab -
					crontab -l | grep -v 'reboot' | crontab -
					rm ~/Limiting_Shut_down.sh
					echo "已关闭限流关机功能"
					;;
				*)
					echo "无效的选择，请输入 Y 或 N。"
					;;
				esac
				;;

			24)
				root_use
				echo "ROOT私钥登录模式"
				echo "------------------------------------------------"
				echo "将会生成密钥对，更安全的方式SSH登录"
				read -p "确定继续吗？(Y/N): " choice

				case "$choice" in
				[Yy])
					clear
					add_sshkey
					;;
				[Nn])
					echo "已取消"
					;;
				*)
					echo "无效的选择，请输入 Y 或 N。"
					;;
				esac
				;;
			66)

				root_use
				echo "一条龙系统调优"
				echo "------------------------------------------------"
				echo "将对以下内容进行操作与优化"
				echo "1. 更新系统到最新"
				echo "2. 清理系统垃圾文件"
				echo -e "3. 设置虚拟内存${huang}1G${bai}"
				echo -e "4. 设置SSH端口号为${huang}5522${bai}"
				echo -e "5. 开放所有端口"
				echo -e "6. 开启${huang}BBR${bai}加速"
				echo -e "7. 设置时区到${huang}上海${bai}"
				echo -e "8. 优化DNS地址到${huang}1111 8888${bai}"
				echo -e "9. 安装常用工具${huang}docker wget sudo tar unzip socat btop${bai}"
				echo "------------------------------------------------"
				read -p "确定一键保养吗？(Y/N): " choice

				case "$choice" in
				[Yy])
					clear

					echo "------------------------------------------------"
					linux_update
					echo -e "[${lv}OK${bai}] 1/9. 更新系统到最新"

					echo "------------------------------------------------"
					linux_clean
					echo -e "[${lv}OK${bai}] 2/9. 清理系统垃圾文件"

					echo "------------------------------------------------"
					new_swap=1024
					add_swap
					echo -e "[${lv}OK${bai}] 3/9. 设置虚拟内存${huang}1G${bai}"

					echo "------------------------------------------------"
					new_port=5522
					new_ssh_port
					echo -e "[${lv}OK${bai}] 4/9. 设置SSH端口号为${huang}5522${bai}"
					echo "------------------------------------------------"
					echo -e "[${lv}OK${bai}] 5/9. 开放所有端口"

					echo "------------------------------------------------"
					bbr_on
					echo -e "[${lv}OK${bai}] 6/9. 开启${huang}BBR${bai}加速"

					echo "------------------------------------------------"
					set_timedate Asia/Shanghai
					echo -e "[${lv}OK${bai}] 7/9. 设置时区到${huang}上海${bai}"

					echo "------------------------------------------------"
					dns1_ipv4="1.1.1.1"
					dns2_ipv4="8.8.8.8"
					dns1_ipv6="2606:4700:4700::1111"
					dns2_ipv6="2001:4860:4860::8888"
					set_dns
					echo -e "[${lv}OK${bai}] 8/9. 优化DNS地址到${huang}1111 8888${bai}"

					echo "------------------------------------------------"
					install_add_docker
					install wget sudo tar unzip socat btop
					echo -e "[${lv}OK${bai}] 9/9. 安装常用工具${huang}docker wget sudo tar unzip socat btop${bai}"
					echo "------------------------------------------------"
					echo -e "${lv}一条龙系统调优已完成${bai}"
					;;
				[Nn])
					echo "已取消"
					;;
				*)
					echo "无效的选择，请输入 Y 或 N。"
					;;
				esac
				;;

			99)
				clear
				server_reboot
				;;
			0)
				s1xu
				;;
			*)
				echo "无效的输入!"
				;;
			esac
			break_end

		done
		;;

	00)
		cd ~
		clear
		echo "更新日志"
		echo "------------------------"
		echo "全部日志: https://raw.githubusercontent.com/kejilion/sh/main/kejilion_sh_log.txt"
		echo "------------------------"
		curl -s https://raw.githubusercontent.com/kejilion/sh/main/kejilion_sh_log.txt | tail -n 35

		sh_v_new=$(curl -s https://raw.githubusercontent.com/kyrxie/tools/main/s1xutools.sh | grep -o 'sh_v="[0-9.]*"' | cut -d '"' -f 2)

		if [ "$sh_v" = "$sh_v_new" ]; then
			echo -e "${lv}你已经是最新版本！${huang}v$sh_v${bai}"
		else
			echo "发现新版本！"
			echo -e "当前版本 v$sh_v        最新版本 ${huang}v$sh_v_new${bai}"
			echo "------------------------"
			read -p "确定更新脚本吗？(Y/N): " choice
			case "$choice" in
			[Yy])
				clear
				curl -sS -O https://raw.githubusercontent.com/kyrxie/tools/main/s1xutools.sh && chmod +x s1xutools.sh
				cp ./s1xutools.sh /usr/local/bin/xx >/dev/null 2>&1
				echo -e "${lv}脚本已更新到最新版本！${huang}v$sh_v_new${bai}"
				break_end
				s1xu
				;;
			[Nn])
				echo "已取消"
				;;
			*) ;;

			esac
		fi
		;;

	0)
		clear
		exit
		;;

	*)
		echo "无效的输入!"
		;;
	esac
	break_end
done
