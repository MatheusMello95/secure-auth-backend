<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
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

        // Generate the secret key
        $google2fa = new Google2FA();
        $secretKey = $google2fa->generateSecretKey();

        // Store the secret key temporarily
        session(['2fa_secret' => $secretKey]);

        // Generate the QR code
        $qrCodeUrl = $google2fa->getQRCodeUrl(
            config('app.name'),
            $user->email,
            $secretKey
        );

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
            'qrCode' => 'data:image/svg+xml;base64,' . $qrCode,
        ]);
    }

    public function verify(Request $request)
    {
        $request->validate([
            'code' => 'required|string|size:6',
        ]);

        $user = $request->user();
        $secretKey = session('2fa_secret');

        if (!$secretKey) {
            return response()->json([
                'success' => false,
                'message' => 'Two-factor authentication setup has expired. Please try again.',
            ], 400);
        }

        // Verify the code
        $google2fa = new Google2FA();
        $valid = $google2fa->verifyKey($secretKey, $request->code);

        if (!$valid) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid verification code.',
            ], 400);
        }

        // Generate recovery codes
        $recoveryCodes = $this->generateRecoveryCodes();

        // Save the secret key and recovery codes
        $user->two_factor_secret = $secretKey;
        $user->two_factor_recovery_codes = json_encode($recoveryCodes);
        $user->two_factor_enabled = true;
        $user->save();

        // Clear the temporary session data
        session()->forget('2fa_secret');

        return response()->json([
            'success' => true,
            'recoveryCodes' => $recoveryCodes,
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
