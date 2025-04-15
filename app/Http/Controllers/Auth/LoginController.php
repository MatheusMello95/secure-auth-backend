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

        // If user has 2FA enabled, require verification
        if ($user->two_factor_enabled) {
            // Create a temporary session to track pending 2FA
            session(['auth.2fa.user_id' => $user->id]);

            return response()->json([
                'requires2FA' => true,
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
            'user' => $user,
        ]);
    }

    public function verify2FA(Request $request)
    {
        $request->validate([
            'code' => 'required|string|size:6',
        ]);

        // Get user ID from the temporary session
        $userId = session('auth.2fa.user_id');

        if (!$userId) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid authentication flow.',
            ], 400);
        }

        $user = User::where('id', $userId)->firstOrFail();

        // Verify the 2FA code
        $google2fa = new Google2FA();
        $valid = $google2fa->verifyKey(
            $user->two_factor_secret,
            $request->code
        );

        if (!$valid) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid authentication code.',
            ], 401);
        }

        // Clear the temporary session
        session()->forget('auth.2fa.user_id');

        // Log the user in
        Auth::login($user);

        // Create a new session
        $this->createUserSession($request, $user);

        // Get token for API authentication
        $token = $user->createToken('auth_token', ['*'], Carbon::now()->addHours(6));

        return response()->json([
            'success' => true,
            'token' => $token->plainTextToken,
            'user' => $user,
        ]);
    }

    public function verifyBackupCode(Request $request)
    {
        $request->validate([
            'code' => 'required|string',
        ]);

        // Get user ID from the temporary session
        $userId = session('auth.2fa.user_id');

        if (!$userId) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid authentication flow.',
            ], 400);
        }

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

        // Clear the temporary session
        session()->forget('auth.2fa.user_id');

        // Log the user in
        Auth::login($user);

        // Create a new session
        $this->createUserSession($request, $user);

        // Get token for API authentication
        $token = $user->createToken('auth_token', ['*'], Carbon::now()->addHours(6));

        return response()->json([
            'success' => true,
            'token' => $token->plainTextToken,
            'user' => $user,
        ]);
    }

    public function logout(Request $request)
    {
        if ($request->user()) {
            // Revoke the token that was used to authenticate the current request
            $request->user()->currentAccessToken()->delete();

            // Mark the current session as terminated
            Session::where('user_id', $request->user()->id)
                ->where('ip_address', $request->ip())
                ->where('user_agent', $request->userAgent())
                ->delete();
        }

        Auth::guard('web')->logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->json([
            'success' => true,
            'message' => 'Successfully logged out',
        ]);
    }

    public function logoutOtherDevices(Request $request)
    {
        $request->validate([
            'password' => 'required|string',
        ]);

        $user = $request->user();

        if (!Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'password' => ['The provided password is incorrect.'],
            ]);
        }

        // Delete all tokens except the current one
        $user->tokens()->where('id', '!=', $user->currentAccessToken()->id)->delete();

        // Delete all sessions except the current one
        Session::where('user_id', $user->id)
            ->where(function ($query) use ($request) {
                $query->where('ip_address', '!=', $request->ip())
                    ->orWhere('user_agent', '!=', $request->userAgent());
            })
            ->delete();

        return response()->json([
            'success' => true,
            'message' => 'All other sessions have been terminated.',
        ]);
    }

    protected function hasTooManyLoginAttempts(Request $request)
    {
        return FailedLoginAttempt::recentAttempts(
            $request->email,
            $request->ip(),
            $this->decayMinutes
        ) >= $this->maxAttempts;
    }

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
