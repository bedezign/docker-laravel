FROM bedezign/php:laravel-fpm

# XDebug
RUN pecl install xdebug && docker-php-ext-enable xdebug \
    && (echo 'php_admin_flag[xdebug.remote_enable] = On;' >> /usr/local/etc/php-fpm.d/www.conf) \
    && (echo 'php_admin_value[xdebug.remote_host] = "host.docker.internal";' >> /usr/local/etc/php-fpm.d/www.conf) \
    && (echo '#!/bin/bash\n/usr/local/bin/php -dxdebug.remote_enable=1 -dxdebug.remote_autostart=1 -dxdebug.remote_host=host.docker.internal "$@"' > /usr/local/bin/php-dbg) \
    && chmod +x /usr/local/bin/php-dbg \
    #
    # Cleanup apt-get stuff
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
