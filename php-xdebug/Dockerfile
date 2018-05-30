FROM php:7-fpm

COPY php-entrypoint /usr/local/bin

RUN apt-get update \
    && apt-get install -y zlib1g-dev lua5.3-dev sudo iputils-ping \
    # LUA
    && cd /usr/include && ln -fs lua5.3/ lua && cd /usr/lib && ln -fs /usr/lib/x86_64-linux-gnu/liblua5.3.so liblua.so \
    && pear config-set http_proxy "$http_proxy" && pear update-channels && pecl install lua && docker-php-ext-enable lua \
    # Regular extensions
    && docker-php-ext-install zip pdo pdo_mysql \
    # Redis & XDebug
    && pecl channel-update pecl.php.net && pecl install redis && pecl install xdebug && docker-php-ext-enable redis xdebug \
    && (echo 'php_admin_flag[xdebug.remote_enable] = On;' >> /usr/local/etc/php-fpm.d/www.conf) \
    && (echo 'php_admin_flag[xdebug.remote_host] = "docker.for.mac.localhost";' >> /usr/local/etc/php-fpm.d/www.conf) \
    # Make entrypoint executable
    && chmod +x /usr/local/bin/php-entrypoint \
    # Cleanup apt-get stuff
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /var/www/html

ENTRYPOINT ["php-entrypoint"]
