<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\FailedLoginAttempt;
use App\Models\Session;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Carbon\Carbon;
use PragmaRX\Google2FA\Google2FA;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Cache;

class LoginController extends Controller
{
    protected $maxAttempts = 5;
    protected $decayMinutes = 10;

    public function csrf(Request $request)
    {
        return response()->json(['csrfToken' => csrf_token()]);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);
        // Check if user is locked out due to too many failed attempts
        if ($this->hasTooManyLoginAttempts($request)) {
            return $this->sendLockoutResponse($request);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            // Record failed login attempt
            FailedLoginAttempt::create([
                'email' => $request->email,
                'ip_address' => $request->ip(),
                'attempted_at' => Carbon::now(),
            ]);

            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }
        \Log::info('User logged in: ' . $user->id);
        // If user has 2FA enabled, require verification
        if ($user->two_factor_enabled) {
            \Log::info('2FA is enabled for user: ' . $user->id);

            // Create a setup key for this verification attempt
            $setupKey = '2fa_login_1_' . Str::random(10);
            \Log::info('Generated setupKey: ' . $setupKey);

            // Store both the user ID and secret in cache
            Cache::put($setupKey, [
                'user_id' => $user->id,
                'secret' => $user->two_factor_secret
            ], now()->addMinutes(15));

            \Log::info('Stored in cache - Key: ' . $setupKey . ', Secret: ' . substr($user->two_factor_secret, 0, 5) . '..., User ID: ' . $user->id);

            return response()->json([
                'requires2FA' => true,
                'setupKey' => $setupKey,
                'message' => 'Please provide your 2FA code.',
            ]);
        }

        // Create a new session
        $this->createUserSession($request, $user);

        // Get token for API authentication
        $token = $user->createToken('auth_token', ['*'], Carbon::now()->addHours(6));

        return response()->json([
            'success' => true,
            'token' => $token->plainTextToken,
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'is_admin' => (bool)$user->is_admin, // Include is_admin as boolean
                'email_verified_at' => $user->email_verified_at,
                'created_at' => $user->created_at,
                'updated_at' => $user->updated_at,
            ],
        ]);
    }

    public function verify2FA(Request $request)
    {
        \Log::info('Received 2FA verification request', [
            'request_body' => $request->all(),
            'content_type' => $request->header('Content-Type')
        ]);

        try {
            $request->validate([
                'code' => 'required|string|size:6',
                'setupKey' => 'required|string',
            ]);

            \Log::info('Validation passed', [
                'code' => $request->code,
                'setupKey' => $request->setupKey
            ]);

            // Get data from cache
            $cacheData = Cache::get($request->setupKey);
            \Log::info('Cache lookup for key: ' . $request->setupKey . ' - Found: ' . ($cacheData ? 'Yes' : 'No'));

            if (!$cacheData) {
                \Log::error('No data found in cache for key: ' . $request->setupKey);
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid authentication flow or expired session.',
                ], 400);
            }

            // Get user ID and secret from cache
            $userId = $cacheData['user_id'] ?? null;
            $twoFactorSecret = $cacheData['secret'] ?? null;

            \Log::info('Retrieved from cache - User ID: ' . ($userId ?? 'null') . ', Secret: ' . (substr($twoFactorSecret ?? '', 0, 5) ?: 'null') . '...');

            if (!$userId || !$twoFactorSecret) {
                \Log::error('Cache data incomplete');
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid authentication data.',
                ], 400);
            }

            // Get the user
            $user = User::find($userId);
            if (!$user) {
                \Log::error('User not found: ' . $userId);
                return response()->json([
                    'success' => false,
                    'message' => 'User not found.',
                ], 404);
            }

            // Verify the 2FA code
            $google2fa = new Google2FA();

            \Log::info('Verifying code: ' . $request->code . ' against secret: ' . substr($twoFactorSecret, 0, 5) . '...');

            $valid = $google2fa->verifyKey(
                $twoFactorSecret,
                $request->code,
                4 // Increase the window to allow for more time variance
            );

            \Log::info('Verification result: ' . ($valid ? 'Valid' : 'Invalid'));

            if (!$valid) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid authentication code.',
                ], 401);
            }

            // Clear the cache
            Cache::forget($request->setupKey);

            // Log the user in
            Auth::login($user);

            // Create a new session
            $this->createUserSession($request, $user);

            // Get token for API authentication
            $token = $user->createToken('auth_token', ['*'], Carbon::now()->addHours(6));

            \Log::info('2FA verification successful, returning token');

            return response()->json([
                'success' => true,
                'token' => $token->plainTextToken,
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'is_admin' => (bool)$user->is_admin, // Make sure this is explicitly cast to boolean
                    'email_verified_at' => $user->email_verified_at,
                    'created_at' => $user->created_at,
                    'updated_at' => $user->updated_at,
                ],
            ]);
        } catch (\Exception $e) {
            \Log::error('Exception in verify2FA: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'An error occurred: ' . $e->getMessage(),
            ], 500);
        }
    }

    public function verifyBackupCode(Request $request)
    {

        try{

            $request->validate([
                'code' => 'required|string',
                'setupKey' => 'required|string', // Add setupKey validation
            ]);

            $cacheData = Cache::get($request->setupKey);

            if (!$cacheData) {
                \Log::error('No data found in cache for key: ' . $request->setupKey);
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid authentication flow or expired session.',
                ], 400);
            }

            // Get user ID and secret from cache
            $userId = $cacheData['user_id'] ?? null;
            $twoFactorSecret = $cacheData['secret'] ?? null;


            $user = User::where('id', $userId)->firstOrFail();

            // Verify backup code
            $recoveryCodes = json_decode($user->two_factor_recovery_codes, true) ?: [];
            $recoveryCodeIndex = array_search($request->code, $recoveryCodes);

            if ($recoveryCodeIndex === false) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid backup code.',
                ], 401);
            }

            // Remove the used backup code
            unset($recoveryCodes[$recoveryCodeIndex]);
            $user->two_factor_recovery_codes = json_encode(array_values($recoveryCodes));
            $user->save();

            // Clear the temporary session and cache
            session()->forget('auth.2fa.user_id');
            if ($request->setupKey) {
                Cache::forget($request->setupKey);
            }

            // Log the user in
            Auth::login($user);

            // Create a new session
            $this->createUserSession($request, $user);

            // Get token for API authentication
            $token = $user->createToken('auth_token', ['*'], Carbon::now()->addHours(6));

            return response()->json([
                'success' => true,
                'token' => $token->plainTextToken,
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'is_admin' => (bool)$user->is_admin,
                    'email_verified_at' => $user->email_verified_at,
                    'created_at' => $user->created_at,
                    'updated_at' => $user->updated_at,
                ],
            ]);
        } catch (\Exception $e) {
            \Log::error('Exception in verify2FA: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'An error occurred: ' . $e->getMessage(),
            ], 500);
        }
    }

    protected function hasTooManyLoginAttempts(Request $request)
    {
        return FailedLoginAttempt::where('email', $request->email)
            ->where('ip_address', $request->ip())
            ->where('attempted_at', '>=', Carbon::now()->subMinutes($this->decayMinutes))
            ->count() >= $this->maxAttempts;
    }

    // Also, make sure this method is defined:
    protected function sendLockoutResponse(Request $request)
    {
        $seconds = $this->decayMinutes * 60;

        throw ValidationException::withMessages([
            'email' => [
                "Too many login attempts. Please try again in {$this->decayMinutes} minutes.",
            ],
        ])->status(429);
    }
    protected function createUserSession(Request $request, User $user)
{
    // Identify device type
    $agent = $request->userAgent();
    $deviceName = 'Unknown Device';

    if (preg_match('/(chrome|safari|firefox|edge|opera)/i', $agent, $matches)) {
        $browser = ucfirst($matches[1]);

        if (preg_match('/(windows|mac|linux|android|iphone|ipad)/i', $agent, $matches)) {
            $os = ucfirst($matches[1]);
            $deviceName = "{$browser} on {$os}";
        } else {
            $deviceName = "{$browser} Browser";
        }
    }

    // Mark all current sessions as not current
    Session::where('user_id', $user->id)
        ->where('is_current', true)
        ->update(['is_current' => false]);

    // Create a new session record
    Session::create([
        'user_id' => $user->id,
        'ip_address' => $request->ip(),
        'user_agent' => $agent,
        'payload' => 'Session data',
        'last_activity' => time(),
        'device_name' => $deviceName,
        'is_current' => true,
    ]);
}
}
