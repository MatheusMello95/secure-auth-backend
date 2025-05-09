<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Password;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class PasswordResetController extends Controller
{
    public function sendResetLink(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
        ]);
        Log::info('User email: ' . $request->email);
        $user = \App\Models\User::where('email', $request->email)->first();

        if($user) {
            Log::info('Email: ' . $user->email);
            // Send reset link (this uses Laravel's built-in notification)
            $status = Password::sendResetLink(
                $request->only('email')
            );

            Log::info('Password reset status: ' . $status);

            return response()->json([
                'success' => true,
                'message' => 'You will receive a password reset link shortly on the email that you type.',
            ]);
        } else {
            Log::info('User nor found');
            return response()->json([
                'success' => false,
                'message' => 'User not found.',
            ]);
        }
    }

    public function reset(Request $request)
    {
        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => [
                'required',
                'confirmed',
                'min:12',             // Minimum 12 characters
                'regex:/[a-z]/',      // At least one lowercase letter
                'regex:/[A-Z]/',      // At least one uppercase letter
                'regex:/[0-9]/',      // At least one digit
                'regex:/[^A-Za-z0-9]/', // At least one special character
            ],
        ], [
            'password.regex' => 'The password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character.',
        ]);

        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user, $password) {
                $user->forceFill([
                    'password' => Hash::make($password),
                    'remember_token' => Str::random(60),
                ])->save();

                // Revoke all existing tokens for security
                $user->tokens()->delete();

                event(new PasswordReset($user));
            }
        );

        if ($status == Password::PASSWORD_RESET) {
            return response()->json([
                'success' => true,
                'message' => 'Your password has been reset. You can now login with your new credentials.',
            ]);
        } else {
            return response()->json([
                'success' => false,
                'message' => 'Unable to reset password. The reset link may have expired or is invalid.',
            ], 400);
        }
    }
}
