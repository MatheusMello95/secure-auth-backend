<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class EnsureSecureCookies
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        $response->headers->setCookie(
            $response->headers->getCookies()[0]->withSecure(true)
                                                ->withHttpOnly(true)
                                                ->withSameSite('lax')
        );

        return $response;
    }
}
