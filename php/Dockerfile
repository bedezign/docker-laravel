FROM php:fpm

COPY php-entrypoint /usr/local/bin

RUN apt-get update \
    && apt-get install -y zlib1g-dev sudo iputils-ping \
    #
    # LUA
    && apt-get install -y lua5.3-dev \
    && cd /usr/include && ln -fs lua5.3/ lua && cd /usr/lib && ln -fs /usr/lib/x86_64-linux-gnu/liblua5.3.so liblua.so \
    && pear config-set http_proxy "$http_proxy" && pear update-channels && pecl install lua && docker-php-ext-enable lua \
    #
    # Regular extensions
    && docker-php-ext-install zip pdo pdo_mysql \
    #
    && pecl channel-update pecl.php.net \
    #
    # Redis
    && pecl channel-update pecl.php.net && pecl install redis && docker-php-ext-enable redis \
    #
    # Make entrypoint executable
    && chmod +x /usr/local/bin/php-entrypoint \
    #
    # Cleanup apt-get stuff
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /var/www/html

ENTRYPOINT ["php-entrypoint"]
