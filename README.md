# Docker (PHP / Laravel)

This repository contains a set of tools that help me start development on new PHP projects in docker quickly, usually on Laravel.
You don't necessarily need to use Laravel for this to be useful for you.

TL;DR: How to setup custom DNS entries for all your `docker-compose` based projects on your Mac (`https://fancy-project.test` instead of `http://localhost:32774/`).

Overview:

* [Repository Contents](#contents)
* [System Setup](#setup)
* [Docker Compose configuration](#configuration)

<a name="contents"></a>
## Repository Contents


### docker-gen

The idea is that we run `nginx` on the host system, which acts as a reverse proxy (and an HTTPS endstop) for all docker containers. This allows saves us from messing arund with the certificates in the containers itself and simplifies a lot of things.

When running everything in docker containers, you usually end up with either a lot of manual configuration, or using port numbers in your browser to test your code. Neither of which I particularly like. So when I discovered Jason Wilders' [docker-gen](https://github.com/jwilder/docker-gen) and its [nginx-proxy](https://github.com/jwilder/nginx-proxy) example, I decided that was the way to go on my Mac.

Wasted a lot of time to get it to do what I wanted, but ended up having to admit defeat with the out-of-the-box setup. The simple fact that you cannot even create a new variable in a Go text/template ruined my efforts. I wanted to create my own variant with PHP. 

#### in depth 

`docker-gen` basically monitors all docker events and whenever a container is started or stopped that would be relevant (in our case, with `onlyexposed = true` in the config this means "containers that expose one or more ports"), it triggers the specified `template` (Go text/template format), stores the template output into `dest` and then runs the `notifycmd`. Since Go's text/template was too limited for me, the only thing the template does is to _jsonify_ the received data structure (referenced as `$`) and then triggers the php script, which will actually do all the work.

### echo

This folder contains the required setup for the [laravel-echo-server](https://www.npmjs.com/package/laravel-echo-server) npm module. This is a NodeJS Socket.IO server for [Laravel Echo](https://laravel.com/docs/master/broadcasting). The Dockerfile, based on [`node:7-alpine`](https://hub.docker.com/_/node/), can be used to quickly setup echo in your environment. The included config file (`laravel-echo-server.json`) further facilitates that setup.

<a name="contents-nginx"></a>
### nginx 

This simply contains a basic `nginx.conf` file for running PHP scripts against `php-fpm`, assuming the container can be reached via `php:9000` within the docker network.
There is also a Dockerfile, based on [`nginx:latest`](https://hub.docker.com/_/nginx/), that simply integrates this config file.

<a name="contents-php"></a>
### php

Dockerfile to build a [`php:7-fpm`](https://hub.docker.com/_/php/) based image that includes extensions lke `zip`, `pdo`, `pdo_mysql`, `redis` and `lua`.

#### php-entrypoint

Custom entrypoint script for the PHP containers facilitating a default laravel project. By adding a `CONTAINER_ROLE` environment setting to your container you can change the command that is ran. Supported is `app`, which just starts `php-fpm` with whatever arguments you've specified, `queue`, which will run `artisan queue:work` (default queue support only at the moment) and `scheduler`, which will trigger `artisan schedule:run` every 60 seconds. 

The script is based on the [Running the Laravel Scheduler and Queue with Docker](https://laravel-news.com/laravel-scheduler-queue-docker) article on the Laravel News site.

#### php/xdebug

Identical to php, but this also installs and configures [XDebug](https://xdebug.org/).

<a name="setup"></a>
## Setting up

_Note: If setup all configuration assuming an as close to linux setup as possible, meaning using `/etc`, but you can change the `docker-gen.conf` and the `.plist` file to change that. Also, it is assumed that nginx is `/sbin/nginx` _

[Homebrew](https://brew.sh/) can install both `nginx` and `docker-gen` for you. 

Copy the `docker-gen.conf`-file to `/etc`, `containers.tmpl` and `nginx-generator.php` go into `/etc/docker-gen.d/`.

Next, we'll start `nginx`. Homebrew provides a service for `nginx` which makes this step really easy, but you'll have to trigger it via `sudo` as well: `sudo brew services start nginx`. If you're not planning on using ports < 1024 this isn't required, but for me it would defeat the purpose entirely.

Since nginx runs as root, anything interacting with its configuration also requires root, meaning `docker-gen`. 
For MacOS, the easiest way is to copy the added `com.bedezign.docker-gen.plist`-file into your `/Library/LaunchDaemons` directory and then use `sudo launchctl load -w /Library/LaunchDaemons/com.bedezign.docker-gen.plist` to activate it. 

(For `systemd`-based OSes, there's `docker-gen.service`, a unit you can use.)

As for system setup, that is all. 

Since the compose setup possibly involves more of the rest of this repostory, it will be explained later on.

If you weant to change the behavior, `nginx-generator.php` supports a number of parameters:

* `--nginx=target`: Specifies the nginx configuration path. Configured as `/etc/nginx/sites-enabled/docker.conf`. If not specified the result will be written to `STDOUT`.
* `--file=/tmp/containers.json`: If you want to use an alternative container input file, or store it somewhere else.
* `--delete`: Delete the container config file when done.
* `--reload[=/sbin/nginx]`: If specified, issue an `nginx -s reload` command. Specifies the nginx binary location if not `/sbin/nginx`

<a name="configuration"></a>
## Docker-Compose

### /etc/hosts
Setting up a new project involves a couple steps. First of all we need to make sure your system can resolve the URL we're about to use. Simplest way is to modify `/etc/hosts` on your Mac:

```
127.0.0.1	fancy-project.test
```

There's 1 caveat here: If you are planning to communicate with containers part of another docker-compose project, you'll have to use a "more global" IP to resolve to. 

Imagine:

```
127.0.0.1	fancy-project.test
127.0.0.1	api.different-fancy-project.test
```
If - in your container - you try to connect to the api of that other fancy project, the Docker DNS will resolve the url to 127.0.0.1 and you'll end up trying to contact yourself. My solution for this (on my mac) is easy: I just add an alias IP to my loopback network interface:

```
sudo ifconfig lo0 alias 172.99.0.100
```

And then my hosts file becomes:

```
172.99.0.100	fancy-project.test
172.99.0.100	api.different-fancy-project.test
```

`172.99.0.100` is something I've been using for a long time, it doesn't have any specific significance.

### nginx

After that we want to make sure we can actually reach our containers. For that we need to configure our system nginx. The php script will only process containers that define a `NGINX_HOST` **label** (**not** environment!). I like to do the more "messy" stuff in my `.env`-file, this allows me to easier override these things for different environment.

What I usually setup in my `.env` for a docker project:

```
PROJECT_URL=fancy-project.test
NGINX_SSL={"cert-path":"/tmp/dev/fancy-project.crt","key-path":"/tmp/dev/fancy-project.key","create":true}
NGINX_SSL_CA={"cert-path":"/etc/ssl/ca.bedezign.pem","key-path":"/etc/ssl/ca.bedezign.key","password":"P455W0RD!"}
APP_URL=https://${PROJECT_URL}
```

 
Basically the `APP_URL` is just there to show that you can also use it within the `.env`.

The service in my `docker-compose.yml`:

```yaml
  nginx:
    build: vendor/bedezign/docker-laravel/nginx
    image: nginx-local:latest
    volumes:
      - .:/var/www/html:ro
    labels:
      NGINX_HOST: ${PROJECT_URL}
      NGINX_SSL: ${NGINX_SSL}
      NGINX_SSL_CA: ${NGINX_SSL_CA}
    ports:
      - 80
```

That is basically all there is too it. 

The configuration above uses a self-built docker image for nginx. Alternative could be to just use the configuration on the default image:

```yaml
  nginx:
    image: nginx:latest
    volumes:
      - .:/var/www/html:ro
      - /vendor/bedezign/docker-laravel/nginx/nginx.conf:/etc/nginx/conf.d/default.conf
```

See [NGinx Technical](#nginx-technical) for a full list and explanation of the support labels.

### php

Using the `CONTAINER_ROLE` function (described under the php-entrypoint section), we'll need a couple of php containers. Instead of repeating the entire service configuration I just like to use anchors and references:

```yaml
x-php-container: &php-container
  build: vendor/bedezign/docker-laravel/php
  image: php-local:latest
  volumes:
    - .:/var/www/html

services:
  php:
    << : *php-container
    environment:
      - CONTAINER_ROLE=app

  cron:
    << : *php-container
    environment:
      - CONTAINER_ROLE=scheduler

  queue:
    << : *php-container
    environment:
      - CONTAINER_ROLE=queue
```

#### Http forwarding and Trusted Proxies

For those for whom the concept Trusted Proxies is new: Since a reverse proxy usually terminates the HTTPS connection and adds a number of other HEADERS to indicate it did, we really need to know for certain that those HEADERS were actually added by our proxy.
(Imagine an attacker posing as a middleman, changing the http requests and simply add a `Front-End-Https` header, tricking your application in believing it was done over HTTPS). To that end the concept "trusted proxy" was invented. It tells your code that those dangerous headers can only be trusted if the request came from our own proxy.

Recent versions of laravel include [fideloper/TrustedProxy](https://github.com/fideloper/TrustedProxy) for this. Normally you'd simply add the IP of your proxy in there and donzo. Unfortunately with docker this is not as simple. The address reported to laravel will be the default gateway of the docker network. Which means this can change between restarts of your project. The simplest solution I found for this is to compare the `REMOTE_ADDR` value against the `SERVER_ADDR` (your own). If the remote ends with `.1` and the rest of the IP is the same as or own, we can assume its our proxy. The `php`-folder contains a `TrustProxies.php` implementation for this, just put it under `app/Http/Middleware`. 

### echo

If you need echo, you can do it like so:
```yaml
  echo:
    build: vendor/bedezign/docker-laravel/echo
    working_dir: /usr/src/app
    volumes:
      - vendor/bedezign/docker-laravel/echo:/usr/src/app
    labels:
      NGINX_HOST: ${PROJECT_URL}
      NGINX_PROXY: "{port: 6001}"
    ports:
      - 80
```
This sets up echo with an external https port of 6001, proxied to local port 80 (non-https, which is what echo likes). 

<a name="nginx-technical"></a>
#### NGinx Technical

There are a number of labels that you can add that influence the generation of the host nginx configuration: 

* `NGINX_HOST`: Tells the configurator under which vhost this container is allocated. If this is not present, the container will be ignored.
* `NGINX_PROXY`: How nginx should proxy connections to your containers. You can either use one of the predefined "templates" or fully define your own:
	* `NGINX_PROXY=https`: (default) Setup a server on the 443 port that accepts ssl/http2 connections and forwards them to the exposed port 80 on your container as HTTP. All appropriate headers are added (including Front-End-Https). A connection upgrade server will be added (connecting to http will redirect to https).
	* `NGINX_PROXY=http`: Setup a proxy from port 80 public to exposed port 80 on your container
	* `NGINX_PROXY=direct`: Forward http traffic from port 80 to container port 80 and 443 https to 443, don't interfere.
	* `NGINX_PROXY=merge`: Setup separate server entries for both port 80 http and 443 https, but forward them to the same container port (handy for development if you want to be able to test non-https traffic)
	* Your own JSON, recognized keys are:
		* `port`: Public port on which nginx will listen (default: `443`)
 		* `protocol`: Public listen protocol (default: `https`)
		* `proxy_port`: Exposed port on your container. This will be "expanded" into the port on the host if the IP is `0.0.0.0` (default: `80`).
 		* `proxy_protocol`: Protocol to proxy with (default: `http`)
 		* `location`: Location to define the proxy on (default: `/`)
* `NGINX_SSL`: Optional configuration for the SSL part of a vhost (JSON). If you don't use SSL, or you are using letsencrypt, you can leave this empty. It will look in `/etc/letsencrypt/live/{NGINX_HOST}`. If you want to use self-signed certificates, we have you covered: the script can auto-generate those for you. Like in the example above, recognised entries are:
	* `cert-path`: Path to the certificate. `/etc/letsencrypt/live/{NGINX_HOST}/fullchain.pem` if empty.
	* `key-path`: Path to the certificate key. `/etc/letsencrypt/live/{NGINX_HOST}/privkey.pem` if empty.  
	* `create`: boolean, default: `false`. If true, this will create a self-signed certificate (if there's no existing one yet). Enabling this without specifying `cert-path` and `key-path` will generate the files in the system temporary directory, to avoid overwriting any let's encrypt certificates if accidentally forgotten. You only need to define this one **for one host**, it will use the same configuration on all identical `NGINX_HOST` entries.
	* `ca-cert-path`, `ca-key-path`, `ca-password`: Entries for `NGINX_SSL_CA` (if you want to keep everything together in a single JSON).
* `NGINX_SSL_CA`: Configuration for signing your certificate with a Certificate Authority. Like `NGINX_SSL` this can contain a `cert-path`, `key-path` and it should also have a `password` entry. Why use this? It's fairly easy to create a CA and import this into your mac keychain (or in firefox) and mark it as trusted. All certificates signed with this CA will automatically get "a green lock" in your browser, enabling all extra functionality. So it's a good idea to do this. You can specify it separately from the `NGINX_SSL` entry in case you want to load this one from somehwere else, it does need a password after all.

_Why `cert-path` etc and not just `cert`?_
Even though it's not implemented yet, I considered allowing to add an entire certificate in the configuration directly, so I'm saving those in case that happens.

Just like the scripts this is based on, an existing `/etc/nginx/proxy.conf` will be included automatically, as will any `/etc/nginx/vhost.d/{NGINX_HOST}`-files

##### Unquoted JSON
If the decode of a JSON string fails, the generator will attempt to decode again after trying to quote property names that might've been unquoted. While this is invalid JSON, some of you might prefer to ommit the quotes to save some room... I can by no means guarantee that this replacement will result in what you intended, so use at your own risk.