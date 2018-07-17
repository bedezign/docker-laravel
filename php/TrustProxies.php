<?php

namespace App\Http\Middleware;

use Closure;
use Fideloper\Proxy\TrustProxies as Middleware;
use Illuminate\Http\Request;

class TrustProxies extends Middleware
{
    /**
     * The trusted proxies for this application.
     *
     * @var array
     */
    protected $proxies = [];

    public function handle(Request $request, Closure $next)
    {
        // The problem with docker is that most of the time we'll see the docker default gateway address as
        // the "REMOTE_ADDR" header. This has been an issue for a while (just google for "docker REMOTE_ADDR")
        // but a solution seems far off.
        // A possible solution is - given that docker adds their own network and the default gateway IP will always end with .1 - to just
        // add the specified REMOTE_ADDR as trusted if it matches our server address. In the default configuration the proxying nginx
        // runs on the same host so it's relatively safe to assume this is correct.
        $remoteAddr = $request->server->get('REMOTE_ADDR');
        $serverAddr = $request->server->get('SERVER_ADDR');
        if ($serverAddr && $remoteAddr) {
            $lastDot = strrpos($serverAddr, '.');
            if ($lastDot !== false && substr($remoteAddr, $lastDot) === '.1' && strpos($remoteAddr, substr($remoteAddr, 0, $lastDot+1)) === 0) {
                $this->proxies[] = $remoteAddr;
            }
        }

        return parent::handle($request, $next);
    }


    /**
     * The headers that should be used to detect proxies.
     *
     * @var string
     */
    protected $headers = Request::HEADER_X_FORWARDED_ALL;
}
