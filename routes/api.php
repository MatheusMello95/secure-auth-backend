<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\Auth\TwoFactorController;
use App\Http\Controllers\Auth\PasswordResetController;
use App\Http\Controllers\SessionController;

Route::get('/test', function () {
    return response()->json(['message' => 'API is working!']);
});
// Public routes
Route::post('/login', [LoginController::class, 'login']);
Route::get('/csrf-token', [LoginController::class, 'csrf']);
Route::post('/verify-2fa', [LoginController::class, 'verify2FA']);
Route::post('/verify-backup-code', [LoginController::class, 'verifyBackupCode']);
Route::post('/password/reset-request', [PasswordResetController::class, 'sendResetLink']);
Route::post('/password/reset', [PasswordResetController::class, 'reset']);

// Protected routes
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [LoginController::class, 'logout']);
    Route::post('/logout-all', [LoginController::class, 'logoutOtherDevices']);

    // Two-factor authentication
    Route::get('/2fa/setup', [TwoFactorController::class, 'enable']);
    Route::post('/2fa/verify', [TwoFactorController::class, 'verify']);
    Route::post('/2fa/disable', [TwoFactorController::class, 'disable']);
    Route::get('/2fa/recovery-codes', [TwoFactorController::class, 'recoveryCodes']);
    Route::post('/2fa/recovery-codes', [TwoFactorController::class, 'regenerateRecoveryCodes']);

    // Session management
    Route::get('/sessions', [SessionController::class, 'index']);
    Route::delete('/sessions/{id}', [SessionController::class, 'destroy']);
    Route::delete('/sessions', [SessionController::class, 'destroyAll']);
});
