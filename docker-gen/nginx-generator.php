<?php
/**
 * This script is the PHP version of Jason Wilders' docker proxying examples but allows for more finegrained configuration
 *
 * The script also works with Labels instead of Env entries as I don't like to add non-relevant entries there.
 * Command line arguments:
 * - nginx=/sbin/nginx          - location of the nginx binary
 * - file=/tmp/containers.json  - File to read the list of containers from
 * - reload                     - if specified, triggers an nginx reload (script might need to be run is root for this)
 * - delete                     - If specified, delete the json file after we're done
 *
 * Recognized docker-compose service labels:
 * NGINX_HOST
 *  (eg "host.domain.tld") This HAS to be set for the container to be included in the nginx configuration.
 *  It allows us to group things per vhost
 * NGINX_SSL_CERT/NGINX_SSL_KEY
 *  By default the script assumes letsencrypt certificates under /etc/letsencrypt/live/{NGINX_HOST}
 *  (fullchain.pem and privkey.pem respectively). Set these labels in any of the linked containers and they will be valid for all of them
 *  (assumption being that you'll only use the one certificat/key for a specific vhost)
 * NGINX_PROXY
 *  Defines how to setup the proxying. You have control over which ports/protocol will be listened on, the location to use and where
 *  to forward traffic to (both exposed port and protocol). Since this will be used the most, there are a number of ways to configure this,
 *  depending on your preference:
 *  - As a "template" by its name.
 *    There are several templates predefined:
 *      "https": (default) Setup a server on the 443 port that accepts ssl/http2 connections and that forwards them to the exposed port 80 on your
 *               container as HTTP. All appropriate headers are added (including Front-End-Https). A connection upgrade server will be added
 *      "http": Setup a proxy from port 80 public to exposed port 80 on your container
 *      "direct": Forward http traffic from port 80 to container port 80 and 443 https to 443
 *      "merge": Setup separate server entries for both port 80 http and 443 https, but forward them to the same container port
 *              (handy for development if you want to be able to test non-https traffic)
 *  - As a json
 *    If you want total control, you can specify the json configuration (either a single entry or an array).
 *    Recognised attributes are (whatever you don't set gets the default value):
 *      - 'port': Public port on which nginx will listen (default: 443)
 *      - 'protocol': Public listen protocol (default: 'https')
 *      - 'proxy_port': Exposed port on your container. This will be "expanded" into the port on the host if the IP is 0.0.0.0  (default: 80)
 *      - 'proxy_protocol' Protocol to proxy with (default: 'http')
 *      - 'location': Location to define the proxy on (default: '/')
 *
 * Varia:
 *  Just like the scripts this is based on, an existing "/etc/nginx/proxy.conf" will be included automatically as will "/etc/nginx/vhost.d/{NGINX_HOST}"-files
 */
$options = getopt('', ['nginx::', 'file::', 'reload::', 'delete']);
$file    = $options['file'] ?? '/tmp/containers.json';
$nginx   = $options['nginx'] ?? null;

// This is just a JSON dump of the docker-gen triggering data - basically the inspect data
// of the involved containers (https://github.com/jwilder/docker-gen)
$containers = file_get_contents($file);
$containers = json_decode($containers, true);
ini_set('display_errors', true);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
function is_sequential($array) { return array_keys($array) === range(0, \count($array) - 1); }

function array_get($array, $key, $default = null, $delimiter = '.')
{
    if (!is_array($array) || null === $key) {
        return $array;
    }

    if (array_key_exists($key, $array)) {
        return $array[$key];
    }

    foreach (explode($delimiter, $key) as $segment) {
        if (is_array($array) && array_key_exists($segment, $array)) {
            $array = $array[$segment];
        } else {
            return $default;
        }
    }

    return $array;
}

if ($nginx) {
    ob_start();
}

echo <<<'EOT'
#
# Automatically generated via docker-gen based on the docker containers running
# DO NOT edit manually
#

# If we receive X-Forwarded-Proto, pass it through; otherwise, pass along the
# scheme used to connect to this server
map $http_x_forwarded_proto $proxy_x_forwarded_proto {
  default $http_x_forwarded_proto;
  ''      $scheme;
}

# If we receive X-Forwarded-Port, pass it through; otherwise, pass along the
# server port the client connected to
map $http_x_forwarded_port $proxy_x_forwarded_port {
  default $http_x_forwarded_port;
  ''      $server_port;
}

# If we receive Upgrade, set Connection to "upgrade"; otherwise, delete any
# Connection header that may have been passed to this server
map $http_upgrade $proxy_connection {
  default upgrade;
  '' close;
}

# Apply fix for very long server names
server_names_hash_bucket_size 128;

# Set appropriate X-Forwarded-Ssl header
map $scheme $proxy_x_forwarded_ssl {
  default off;
  https on;
}

gzip_types text/plain text/css application/javascript application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;

log_format vhost '[$time_local] $remote_addr - $remote_user [$server_name -> $upstream_addr] '
                 '"$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent"';

access_log off;
EOT;

if (file_exists('/etc/nginx/proxy.conf')) {
    echo 'include /etc/nginx/proxy.conf;', PHP_EOL;
} else {
    echo <<<'EOT'
# HTTP 1.1 support
proxy_http_version 1.1;
proxy_buffering off;
proxy_set_header Host $http_host;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $proxy_connection;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $proxy_x_forwarded_proto;
proxy_set_header X-Forwarded-Ssl $proxy_x_forwarded_ssl;
proxy_set_header X-Forwarded-Port $proxy_x_forwarded_port;
add_header Front-End-Https   on;

# Mitigate httproxy attack
proxy_set_header Proxy "";

EOT;
}
// Group containers per VHOST, ignore those that don't have any (starts off with groupByLabel $ "NGINX_HOST" in the template)
$hosts = [];
foreach ($containers as $container) {
    $host = array_get($container, 'Labels.NGINX_HOST');
    if ($host) {
        if (!array_key_exists($host, $hosts)) {
            $hosts[$host] = ['containers' => [], 'ssl' => ['cert' => "/etc/letsencrypt/live/$host/fullchain.pem", 'key' => "/etc/letsencrypt/live/$host/privkey.pem"]];
        }
        $hosts[$host]['containers'][] = $container;
        $hosts[$host]['ssl']['cert']  = array_get($container, 'Labels.NGINX_SSL_CERT', $hosts[$host]['ssl']['cert']);
        $hosts[$host]['ssl']['key']   = array_get($container, 'Labels.NGINX_SSL_KEY', $hosts[$host]['ssl']['key']);
    }
}

foreach ($hosts as $hostname => $data) {
    $ports = [];
    echo <<<EOT
############
#
#  $hostname
#
############

EOT;

    $defaultProxy = ['port' => 443, 'protocol' => 'https', 'proxy_port' => 80, 'proxy_protocol' => 'http', 'location' => '/'];
    foreach ($data['containers'] as $container) {
        $proxies = [];

        $proxyingType = array_get($container, 'Labels.NGINX_PROXY', 'https');
        switch ($proxyingType) {
            // Only HTTP externally to HTTP on container
            case 'http' :
                $proxies = [[80, 'http']];
                break;
            // Define a server on HTTPS externally and proxy to HTTP on the container (with auto HTTPS upgrade server) - default behaviour (preferred for production)
            case 'https':
                $proxies = [$defaultProxy];
                break;
            // Only HTTP and HTTPS externally to HTTP and HTTPS on container
            case 'direct' :
                $proxies = [[80, 'http'], [443, 'https', 443, 'https']];
                break;
            // Listen to both HTTP and HTTPS externally, but merge to HTTP on container
            case 'merge' :
                $proxies = [[80, 'http'], [443, 'https']];
                break;

            default:
                // As a fallback, allow for a json string and as a courtesy, make sure unquoted property names are quoted, even though its invalid JSON
                $json = json_decode(preg_replace("/(['\"])?(\w+)(['\"])?:/", '"$2":', $proxyingType), true);
                if ($json) {
                    // Either its an indexed array (don't touch it) or its associative (wrap in an extra layer)
                    if (is_sequential($json)) {
                        // We'll still wrap it in an extra array if the first element is not an array itself,
                        // this means the user just specified the values in order
                        $proxies = is_array(reset($json)) ? $json : [$json];
                    }
                    else {
                        $proxies = [$json];
                    }
                }
                break;
        }

        foreach ($proxies as $proxy) {

            // Sequential array?
            if (is_sequential($proxy)) {
                // Make sure we have default values for everything
                $proxy += array_values($defaultProxy);
                ksort($proxy, SORT_NUMERIC);
                // assign correct keys
                $proxy = array_combine(array_keys($defaultProxy), $proxy);
            } else {
                // Associative but not everything has to be set, be sure to define default values.
                $proxy = array_merge($defaultProxy, $proxy);
            }

            $ports []       = $publicPort = array_get($proxy, 'port', 443);
            $publicProtocol = array_get($proxy, 'protocol', 'https');
            $proxyPort      = array_get($proxy, 'proxy_port', 80);
            $proxyProtocol  = array_get($proxy, 'proxy_protocol', 'https');
            $location       = array_get($proxy, 'location', '/');
            $proxyUrl       = '';
            $vhostConfig    = file_exists($vhostConfig = "/etc/nginx/vhost.d/$hostname") ? PHP_EOL . 'include ' . $vhostConfig : '';


            // Figure the proxy URL.
            // If the HostPort is empty, it is assumed that the HostIP specifies a dedicated IP and that we can use the
            // specified proxy-port.
            $addresses = array_get($container, 'Addresses', []);
            foreach ($addresses as $address) {
                if ((int)array_get($address, 'Port') === $proxyPort) {
                    $proxyUrl = $proxyProtocol . '://' .
                        ($address['HostIP'] === '0.0.0.0' ? '127.0.0.1' : $address['HostIP']) . ':' .
                        (($hostPort = array_get($address, 'HostPort')) ? $hostPort : $proxyPort) .
                        // Per http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass,
                        // by specifying an URI, whatever is specified as "location" will be cut off from the target URI
                        '/';
                }
            }

            if ($publicProtocol === 'https') {

                // Listening on HTTPS, setup standard
                echo <<<EOT
server {
    server_name {$hostname};
    listen {$publicPort} ssl http2;
    error_log  /var/log/nginx/{$hostname}.error.log;
    access_log /var/log/nginx/{$hostname}.access.log vhost;

    # https://mozilla.github.io/server-side-tls/ssl-config-generator/?server=nginx-1.13.8&openssl=1.0.2k&hsts=yes&profile=intermediate
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:!DSS';
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 5m;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    ssl_certificate {$data['ssl']['cert']};
    ssl_certificate_key {$data['ssl']['key']}; $vhostConfig
                
    location $location {
        proxy_pass $proxyUrl;
    }
}

EOT;
            } else {
                echo <<<EOT
server {
    server_name {$hostname};
    listen {$publicPort};
    
    error_log  /var/log/nginx/{$hostname}.error.log;
    access_log /var/log/nginx/{$hostname}.access.log vhost;

    location $location {
        proxy_pass $proxyUrl;
    }
}

EOT;

            }

            echo PHP_EOL;
        }
    }

// If we have defined a port 443, but not 80, add a connection upgrade section
    if (in_array(443, $ports) && !in_array(80, $ports)) {
        echo <<<EOT
server {
    listen       80;
    server_name  $hostname;
    return 301 https://\$host\$request_uri;
}

EOT;
    }

    echo PHP_EOL;
}

if ($nginx) {
    $configuration = ob_get_clean();
    file_put_contents($nginx, $configuration);
}

if (array_key_exists('reload', $options)) {
    $nginx = $options['reload'] ? $options['reload'] : '/sbin/nginx';
    shell_exec($nginx . ' -s reload');
}

if (array_key_exists('delete', $options)) {
    unlink($file);
}