FROM php:8.3-fpm-bookworm

ARG WORDPRESS_VERSION=7.1
ARG WPCLI_VERSION=2.12.0
ARG XDEBUG_VERSION=3.5.3
ARG SNUFFLEUPAGUS_VERSION=0.14.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nginx supervisor curl ca-certificates \
        libpng-dev libjpeg62-turbo-dev libwebp-dev libfreetype6-dev libzip-dev libicu-dev libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-configure gd --with-jpeg --with-webp --with-freetype \
    && docker-php-ext-install -j"$(nproc)" mysqli gd zip exif intl bcmath \
    && pecl install "xdebug-${XDEBUG_VERSION}" \
    && docker-php-ext-enable xdebug

# git is a build-time dependency of this layer only: it is installed, used for the
# clone, and purged again before the layer is committed, so no VCS client ships in
# the runtime image the sample gets to run inside.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && git clone --depth 1 --branch "v${SNUFFLEUPAGUS_VERSION}" https://github.com/jvoisin/snuffleupagus.git /usr/src/snuffleupagus \
    && cd /usr/src/snuffleupagus/src \
    && phpize && ./configure --enable-snuffleupagus \
    && make -j"$(nproc)" && make install \
    && cd / && rm -rf /usr/src/snuffleupagus \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/*

# WP-CLI, checksum-verified against the published .sha512 like the WordPress tarball is.
RUN curl -fsSL -o /usr/local/bin/wp-cli.phar "https://github.com/wp-cli/wp-cli/releases/download/v${WPCLI_VERSION}/wp-cli-${WPCLI_VERSION}.phar" \
    && curl -fsSL -o /tmp/wp-cli.sha512 "https://github.com/wp-cli/wp-cli/releases/download/v${WPCLI_VERSION}/wp-cli-${WPCLI_VERSION}.phar.sha512" \
    && echo "$(cat /tmp/wp-cli.sha512)  /usr/local/bin/wp-cli.phar" | sha512sum -c - \
    && rm -f /tmp/wp-cli.sha512 \
    && chmod 0755 /usr/local/bin/wp-cli.phar

RUN mkdir -p /usr/src/wordpress \
    && curl -fsSL -o /tmp/wp.tgz "https://wordpress.org/wordpress-${WORDPRESS_VERSION}.tar.gz" \
    && curl -fsSL -o /tmp/wp.sha1 "https://wordpress.org/wordpress-${WORDPRESS_VERSION}.tar.gz.sha1" \
    && echo "$(cat /tmp/wp.sha1)  /tmp/wp.tgz" | sha1sum -c - \
    && tar -xzf /tmp/wp.tgz -C /usr/src/wordpress --strip-components=1 \
    && rm -f /tmp/wp.tgz /tmp/wp.sha1

COPY wp-wrapper.sh /usr/local/bin/wp
COPY php/conf.d/ /usr/local/etc/php/conf.d/
COPY php/sp.rules /usr/local/etc/php/sp.rules
COPY php/php-fpm.d/zz-sandbox.conf /usr/local/etc/php-fpm.d/zz-sandbox.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisor/supervisord.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/wp \
    && mkdir -p /var/www/html /var/log/sandbox/xdebug /var/log/sandbox/sp-dumps /var/log/sandbox/php /var/lib/nginx \
    && chown -R www-data:www-data /var/www/html /var/log/sandbox /var/lib/nginx /var/log/nginx /usr/src/wordpress \
    && rm -f /etc/nginx/sites-enabled/default

USER www-data
WORKDIR /var/www/html
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
