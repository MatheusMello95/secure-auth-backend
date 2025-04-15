<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\Session;
use Carbon\Carbon;

class PruneOldSessions extends Command
{
    protected $signature = 'auth:prune-sessions';
    protected $description = 'Prune old inactive sessions';

    public function handle()
    {
        // Delete sessions older than 30 days
        $cutoff = Carbon::now()->subDays(30)->timestamp;

        $count = Session::where('last_activity', '<', $cutoff)->delete();

        $this->info($count . ' old sessions pruned.');

        return 0;
    }
}
