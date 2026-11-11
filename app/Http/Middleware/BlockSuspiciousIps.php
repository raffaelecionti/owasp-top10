<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;
use Symfony\Component\HttpFoundation\Response;

class BlockSuspiciousIps
{

protected $maxAttempts = 5;
protected $decayMinutes = 1;
protected $blockMinutes = 1;
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response

    {
       $ip = $request->ip();
       $key = $this->throttleKey($ip);

       if (Cache::has($key . ':blocked')) {
        Session::flash('error', "Your IP has been blocked for $this->blockMinutes minutes(s) due to suspicious activity.");
        return redirect()->back();
       }
    if(Cache::has($key)) {
        $attempts = Cache::increment($key);
        if ($attempts > $this->maxAttempts) {
            Cache::put($key . ':blocked', true, now()->blockMinutes * 60);
            Log::warning("IP has been blocked for $this->blockMinutes minutes (s) due to suspicious activity: $ip");
            Session::flash('error', "Your IP has been blocked for $this->blockMinutes minutes(s) due to too many requests.");
            return redirect()->back();
        }


    }else {
        Cache::put($key, 1, $this->decayMinutes * 60);
    }

        return $next($request);
    }

    public function throttleKey($ip)
    {
        return 'throttle:' . sha1($ip);
    }
}
