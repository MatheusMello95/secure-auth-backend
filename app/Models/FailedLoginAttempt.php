<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Carbon\Carbon;

class FailedLoginAttempt extends Model
{
    use HasFactory;

    protected $fillable = [
        'email',
        'ip_address',
        'attempted_at',
    ];

    protected $casts = [
        'attempted_at' => 'datetime',
    ];

    public static function recentAttempts($email, $ip, $minutes = 10)
    {
        return static::where('email', $email)
            ->where('ip_address', $ip)
            ->where('attempted_at', '>=', Carbon::now()->subMinutes($minutes))
            ->count();
    }
}
