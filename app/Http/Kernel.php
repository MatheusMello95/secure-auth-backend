<?php

namespace App\Http;

use Illuminate\Foundation\Http\Kernel as HttpKernel;
use App\Http\Middleware\EnsureSecureCookies;
class Kernel extends HttpKernel
{
    protected $middlewareGroups = [
        'web' => [
            // Other middleware
            EnsureSecureCookies::class,
        ],
    ];
}
