# monitoring

```bash
sudo apt-get update
sudo apt-get install -y php-cli php-fpm php-sqlite3 tcpdump
# (ou php-mysql si MySQL)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
```

```bash
php monitor.php
```
