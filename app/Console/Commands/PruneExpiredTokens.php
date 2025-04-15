<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Laravel\Sanctum\PersonalAccessToken;
use Carbon\Carbon;

class PruneExpiredTokens extends Command
{
    protected $signature = 'auth:prune-tokens';
    protected $description = 'Prune expired authentication tokens';

    public function handle()
    {
        $expiration = config('sanctum.expiration');

        if (!$expiration) {
            $this->info('Token expiration is not set. No tokens pruned.');
            return 0;
        }

        $cutoff = Carbon::now()->subMinutes($expiration);

        $tokens = PersonalAccessToken::where('created_at', '<', $cutoff)->get();

        foreach ($tokens as $token) {
            $token->delete();
        }

        $this->info($tokens->count() . ' expired tokens pruned.');

        return 0;
    }
}
