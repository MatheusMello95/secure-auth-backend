<?php

namespace App\Console;

use Illuminate\Console\Scheduling\Schedule;

class Kernel
{

    protected function schedule(Schedule $schedule)
    {
        $schedule->command('auth:prune-tokens')->daily();
        $schedule->command('auth:prune-sessions')->daily();
    }
}
