<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Auth\AuthenticationException;
use Symfony\Component\HttpFoundation\Response;

class EnsureTokenIsValid
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Check if the user is authenticated via Sanctum
        if (!$request->user()) {
            throw new AuthenticationException('Unauthenticated.');
        }

        // Additional security checks can be added here
        // For example, checking if the user account is active, not locked, etc.

        return $next($request);
    }
}
