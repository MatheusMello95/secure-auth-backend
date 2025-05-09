<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Cache;
use PragmaRX\Google2FA\Google2FA;
use Illuminate\Support\Str;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Carbon\Carbon;

class TwoFactorController extends Controller
{
    public function enable(Request $request)
    {
        $user = $request->user();
        Log::info('Starting 2FA setup for user: ' . $user->id);

        // Generate the secret key
        $google2fa = new Google2FA();
        $secretKey = $google2fa->generateSecretKey();
        Log::info('Generated secret key: ' . $secretKey);

        // Create a unique key for this setup attempt
        $setupKey = '2fa_secret_' . $user->id . '_' . Str::random(10);

        // Store in both session and cache for redundancy
        session(['2fa_secret' => $secretKey]);
        session(['2fa_setup_key' => $setupKey]);

        // Also store in cache with 15 minute expiration
        Cache::put($setupKey, $secretKey, now()->addMinutes(15));

        Log::info('2FA setup key generated: ' . $setupKey);

        // Generate the QR code with a proper URI format that works with Google Authenticator
        $company = config('app.name', 'YourApp');
        $qrCodeUrl = $google2fa->getQRCodeUrl(
            $company,
            $user->email,
            $secretKey
        );

        Log::info('QR Code URL: ' . $qrCodeUrl);

        // Convert to SVG
        $writer = new Writer(
            new ImageRenderer(
                new RendererStyle(200),
                new SvgImageBackEnd()
            )
        );

        $qrCode = base64_encode($writer->writeString($qrCodeUrl));

        return response()->json([
            'success' => true,
            'secretKey' => $secretKey,
            'setupKey' => $setupKey,
            'qrCode' => 'data:image/svg+xml;base64,' . $qrCode,
        ]);
    }

    public function verify(Request $request)
    {
        Log::info('Starting 2FA verification');

        $request->validate([
            'code' => 'required|string',
            'setupKey' => 'required|string',
        ]);

        $user = $request->user();
        Log::info('Verifying 2FA for user: ' . $user->id);

        // Try to get the secret key from cache first, then fallback to session
        $setupKey = $request->setupKey;
        Log::info('Setup key from request: ' . $setupKey);

        $secretKey = Cache::get($setupKey);

        // If not in cache, try from session
        if (!$secretKey) {
            $secretKey = session('2fa_secret');
            Log::info('No key in cache, using session key: ' . ($secretKey ? 'present' : 'missing'));
        } else {
            Log::info('Secret key found in cache: ' . $secretKey);
        }

        if (!$secretKey) {
            return response()->json([
                'success' => false,
                'message' => 'Two-factor authentication setup has expired. Please try again.',
            ], 400);
        }

        // Clean the code - remove spaces and make uppercase
        $code = str_replace(' ', '', $request->code);
        Log::info('Verifying code: ' . $code . ' (length: ' . strlen($code) . ')');
        Log::info('Server time: ' . time() . ', Current time period: ' . floor(time() / 30));

        // Verify the code with a much larger time window
        $google2fa = new Google2FA();
        $google2fa->setWindow(16); // Allow very large time drift (8 minutes before and after)

        // Ensure proper key format - sometimes the key needs to be base32 encoded
        // Google2FA expects base32 encoded keys
        if (!preg_match('/^[A-Z2-7]+$/', $secretKey)) {
            Log::info('Secret key is not in base32 format, attempting to convert');
            // If conversion is needed, you could add it here
        }

        try {
            $valid = $google2fa->verifyKey($secretKey, $code);
            Log::info('Code verification result: ' . ($valid ? 'valid' : 'invalid'));

            if (!$valid) {
                Log::info('Verification failed for code: ' . $code);

                // Try with different implementations - sometimes there are differences in how
                // different apps generate codes
                // This is just for debugging purposes
                for ($timeOffset = -8; $timeOffset <= 8; $timeOffset++) {
                    $timestamp = time() + ($timeOffset * 30);
                    $timePeriod = floor($timestamp / 30);
                    Log::info("Checking with time offset {$timeOffset}, period {$timePeriod}");

                    // We'd need to manually generate a code here for debugging, but we'll skip
                    // that in this implementation and just log the offsets we're trying
                }

                return response()->json([
                    'success' => false,
                    'message' => 'Invalid verification code. Please make sure your authenticator app is synced correctly.',
                ], 400);
            }

            // Generate recovery codes
            $recoveryCodes = $this->generateRecoveryCodes();

            // Save the secret key and recovery codes
            $user->two_factor_secret = $secretKey;
            $user->two_factor_recovery_codes = json_encode($recoveryCodes);
            $user->two_factor_enabled = true;
            $user->save();

            // Clear the temporary storage
            session()->forget(['2fa_secret', '2fa_setup_key']);
            Cache::forget($setupKey);

            Log::info('2FA successfully enabled for user: ' . $user->id);

            return response()->json([
                'success' => true,
                'recoveryCodes' => $recoveryCodes,
            ]);
        } catch (\Exception $e) {
            Log::error('2FA verification error: ' . $e->getMessage());
            Log::error($e->getTraceAsString());
            return response()->json([
                'success' => false,
                'message' => 'An error occurred during verification. Please try again.',
            ], 500);
        }
    }

    public function status(Request $request)
    {
        $user = $request->user();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized'
            ], 401);
        }

        return response()->json([
            'success' => true,
            'enabled' => (bool) $user->two_factor_enabled,
            'has_recovery_codes' => !empty($user->two_factor_recovery_codes)
        ]);
    }

    public function disable(Request $request)
    {
        $request->validate([
            'password' => 'required|string',
        ]);

        $user = $request->user();

        if (!Hash::check($request->password, $user->password)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid password.',
            ], 401);
        }

        $user->two_factor_secret = null;
        $user->two_factor_recovery_codes = null;
        $user->two_factor_enabled = false;
        $user->save();

        return response()->json([
            'success' => true,
            'message' => 'Two-factor authentication has been disabled.',
        ]);
    }

    public function recoveryCodes(Request $request)
    {
        $user = $request->user();

        if (!$user->two_factor_enabled) {
            return response()->json([
                'success' => false,
                'message' => 'Two-factor authentication is not enabled.',
            ], 400);
        }

        $recoveryCodes = json_decode($user->two_factor_recovery_codes, true) ?: [];

        return response()->json([
            'success' => true,
            'recoveryCodes' => $recoveryCodes,
        ]);
    }

    public function regenerateRecoveryCodes(Request $request)
    {
        $user = $request->user();

        if (!$user->two_factor_enabled) {
            return response()->json([
                'success' => false,
                'message' => 'Two-factor authentication is not enabled.',
            ], 400);
        }

        // Generate new recovery codes
        $recoveryCodes = $this->generateRecoveryCodes();

        $user->two_factor_recovery_codes = json_encode($recoveryCodes);
        $user->save();

        return response()->json([
            'success' => true,
            'recoveryCodes' => $recoveryCodes,
        ]);
    }

    protected function generateRecoveryCodes($count = 8)
    {
        $codes = [];

        for ($i = 0; $i < $count; $i++) {
            $codes[] = $this->generateRecoveryCode();
        }

        return $codes;
    }

    protected function generateRecoveryCode()
    {
        $segments = [];

        for ($i = 0; $i < 4; $i++) {
            $segments[] = Str::upper(Str::random(4));
        }

        return implode('-', $segments);
    }
}
