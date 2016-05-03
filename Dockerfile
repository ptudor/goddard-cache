FROM alpine:3.3

MAINTAINER ptudor

LABEL Version 201513

#RUN echo "http://dl-4.alpinelinux.org/alpine/3.3/main" >> /etc/apk/repositories
# i wish phpredis was still in this list but libicu blah blah
RUN apk update && \
	apk add --update libidn libidn-dev libintl gettext gettext-dev \
	  openssl redis php-dev php-zlib php-openssl php-json \
	  php-intl php-iconv php-mcrypt php-gettext php-curl php-sqlite3 \
	  autoconf file g++ libc-dev make pkgconf re2c \
	  apache2 apache2-proxy php-fpm make gcc libc-dev perl wget curl && \
	rm -rf /var/cache/apk/* && \
	echo done

# first option, run whois
RUN echo "whois" && cd /tmp/ && wget -q https://github.com/rfc1036/whois/archive/next.zip && \
	unzip next.zip && rm next.zip && cd whois-next && \
	echo "PIC for libraries, PIE for exes" && \
  	export CFLAGS='-O2 -fPIC -fPIE -fstack-protector-all' && \
	export LDFLAGS="-lintl -lidn -pie -Wl,-z,now" && \
        export DEFS="-DHAVE_LIBIDN" && \
	make depend && make && make install && \
	cd /tmp/ && rm -Rf ./whois-next && echo done

# default option, run cowsay
RUN echo "cowsay" && cd /tmp/ && wget -q https://github.com/schacon/cowsay/archive/master.zip && \
	unzip master.zip && rm master.zip && cd cowsay-master && \
	./install.sh /usr && cd /tmp && rm -Rf cowsay-master && \
	/usr/bin/cowsay -f stegosaurus "done!"

ENV VERSION_PHPREDIS="2.2.7" SHA1SUM_PHPREDIS="741a2a37d09a1c6f42c2ff8811ac471618d9f504"
#  && echo $SHA1SUM_PHPREDIS /tmp/phpredis.zip | sha1sum -c - \
RUN echo "== starting phpredis" && \
	wget -q https://github.com/phpredis/phpredis/archive/"${VERSION_PHPREDIS}".zip -O /tmp/phpredis.zip && \
	cd /tmp && unzip phpredis.zip && cd /tmp/phpredis-"${VERSION_PHPREDIS}" && \
	phpize && CFLAGS="-O3 -fPIC -fPIE -fstack-protector-all -fno-strict-aliasing" ./configure && \
	make && make install && make clean && \
	rm -Rf /tmp/phpredis-"${VERSION_PHPREDIS}" && rm -f /tmp/phpredis.zip && \
	/usr/bin/cowsay "phpredis done!"

# redis options. 100mb limit, if it reaches that on 2kb objects, well done.
# also kill that antiquated prefork in Apache.
RUN sed -i -e "s/tcp-keepalive 0/tcp-keepalive 600/g" /etc/redis.conf && \
	echo "maxmemory 100mb" >> /etc/redis.conf && \
	echo "maxmemory-policy allkeys-lru" >> /etc/redis.conf && \
	echo "requirepass oce-6EA-zd2" >> /etc/redis.conf && \
	mkdir -p /run/apache2 && \
	sed -i -e "s/^ScriptAlias/#ScriptAlias/g" /etc/apache2/httpd.conf  && \
	sed -i -e "s/^ServerSignature On/ServerSignature Off/g" /etc/apache2/httpd.conf  && \
	sed -i -e "s/^ServerTokens OS/ServerTokens Prod/g" /etc/apache2/httpd.conf  && \
	sed -i -e "s/^/#/g" /etc/apache2/conf.d/proxy.conf && \
	sed -i -e "s/#LoadModule proxy_module/LoadModule proxy_module/g" /etc/apache2/conf.d/proxy.conf && \
	sed -i -e "s/#LoadModule proxy_fcgi_module/LoadModule proxy_fcgi_module/g" /etc/apache2/conf.d/proxy.conf && \
	sed -i -e "s/^#LoadModule rewrite_module/LoadModule rewrite_module/g" /etc/apache2/httpd.conf  && \
	sed -i -e "s/^LoadModule status_module/#LoadModule status_module/g" /etc/apache2/httpd.conf  && \
	sed -i -e "s/^LoadModule mpm_prefork_module/#LoadModule mpm_prefork_module/g" /etc/apache2/httpd.conf  && \
	sed -i -e "s/#LoadModule mpm_event_module/LoadModule mpm_event_module/g" /etc/apache2/httpd.conf 
	#sed -i -e "s/^/#/g" /etc/apache2/conf.d/httpd-dav.conf && \
	#sed -i -e "s/^/#/g" /etc/apache2/conf.d/ldap.conf && \
	#sed -i -e "s/^/#/g" /etc/apache2/conf.d/lua.conf && \

# enable modules in php-fpm
RUN for ii in redis.so json.so openssl.so zlib.so intl.so iconv.so mcrypt.so gettext.so curl.so ; do \
	echo  "php_admin_value[extension] = $ii"  >> /etc/php/php-fpm.conf ; done

# gotta add this one by hand
RUN echo "extension=redis.so" > /etc/php/conf.d/redis.ini

# not actually using sessions yet but here's the first step
RUN echo "php_admin_value[session.hash_bits_per_character] = 6" >> /etc/php/php-fpm.conf && \
        echo "php_admin_value[session.hash_function] = sha256" >> /etc/php/php-fpm.conf && \
        echo "php_admin_value[session.entropy_length] = 4" >> /etc/php/php-fpm.conf && \
        echo "php_admin_value[session.gc_maxlifetime] = 86400" >> /etc/php/php-fpm.conf && \
        echo "php_admin_value[session.name] = GODDARD" >> /etc/php/php-fpm.conf && \
	echo "php_admin_value[session.save_handler] = redis" >> /etc/php/php-fpm.conf && \
	echo "php_admin_value[session.save_path] = \"tcp://127.0.0.1:6379?database=1&auth=oce-6EA-zd2\"" >> /etc/php/php-fpm.conf

# Now, for some Inception.
# The repo this dockerfile lives in clones itself. 
# stupid and a waste of bandwidth, but it provides
# a way to decouple the Dockerfile from all the other files.
# RUN git clone https://github.com/ptudor/goddard-cache \
#     && cd goddard-cache \
#     && cp alpine-php-fpm.conf /etc/apache2/conf.d/alpine-php-fpm.conf \
#     && cp httpd-goddard-cache.conf /etc/apache2/conf.d/httpd-goddard-cache.conf \
#     && cp html/index-default.html /var/www/localhost/htdocs/index.html \
#     && cp html/robots.txt /var/www/localhost/htdocs/robots.txt \
#     && cp src/goddard-cache.php /var/www/localhost/htdocs/goddard-cache.php \
#     && cp src/config-goddard.php /var/www/localhost/htdocs/config-goddard.php 

WORKDIR  /var/www/localhost/htdocs

# this does the fcgi pass for php extensions
ADD conf/alpine-php-fpm.conf /etc/apache2/conf.d/alpine-php-fpm.conf
# rewrite rules for pretty urls
ADD conf/httpd-goddard-cache.conf /etc/apache2/conf.d/httpd-goddard-cache.conf
# default form
ADD html/index-default.html /var/www/localhost/htdocs/index.html
# default robots
ADD html/robots.txt /var/www/localhost/htdocs/robots.txt
# actual CGI
ADD src/goddard-cache.php /var/www/localhost/htdocs/goddard-cache.php
# default configuration that should be superseded by a config.php
ADD src/config-goddard.php /var/www/localhost/htdocs/config-goddard.php

### SITE SPECIFIC CONFIGURATION. BUILD FAILS HERE UNTIL YOU CREATE THESE.
ADD site-specific/config.php /var/www/localhost/htdocs/config.php
ADD site-specific/index.html /var/www/localhost/htdocs/index.html

# init script for redis, php-fpm, and apache
ADD start-all.sh /start-all.sh

EXPOSE 80 443
CMD ["/start-all.sh"]
#CMD sleep 3600
