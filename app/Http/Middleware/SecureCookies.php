<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;

class SecureCookies
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        // Apply secure attributes to all cookies in the response
        if ($response->headers->has('Set-Cookie')) {
            $cookies = $response->headers->getCookies();
            $response->headers->setCookies([]);

            foreach ($cookies as $cookie) {
                // Set HttpOnly flag (prevents JavaScript access to cookie)
                $cookie->setHttpOnly(true);

                // Set Secure flag (only sent over HTTPS)
                // In production, always true. In development, based on HTTPS
                $secure = App::environment('production') ? true : $request->secure();
                $cookie->setSecure($secure);

                // Set SameSite attribute (protects against CSRF)
                // 'lax' is a good default value for most applications
                $cookie->setSameSite('lax');

                $response->headers->setCookie($cookie);
            }
        }

        // Add security headers
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');

        // Enable Strict Transport Security in production
        if (App::environment('production')) {
            $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }

        return $response;
    }
}
