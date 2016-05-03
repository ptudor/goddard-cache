#!/bin/sh

# do a little sanitizing for the php-fpm.conf url
authkey=`openssl rand 24 -base64 | sed "s/[+=/\,:$&]/-/g" `
echo "setting password: $authkey"
sed -i -e "s/oce-6EA-zd2/$authkey/g" /etc/redis.conf
sed -i -e "s/oce-6EA-zd2/$authkey/g" /etc/php/php-fpm.conf
sed -i -e "s/oce-6EA-zd2/$authkey/g" /var/www/localhost/htdocs/goddard-cache.php
unset $authkey

echo -n "starting... "
php-fpm && \
echo -n "php-fpm "
redis-server /etc/redis.conf && \
echo -n "redis-server "
echo "httpd"
#sleep 3600
httpd -DFOREGROUND
