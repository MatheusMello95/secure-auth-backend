<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Session;
use Carbon\Carbon;

class SessionController extends Controller
{
    public function index(Request $request)
    {
        $user = $request->user();

        $sessions = Session::where('user_id', $user->id)
            ->orderBy('last_activity', 'desc')
            ->get()
            ->map(function ($session) use ($request) {
                return [
                    'id' => $session->id,
                    'device' => $session->device_name,
                    'ipAddress' => $session->ip_address,
                    'lastActive' => Carbon::createFromTimestamp($session->last_activity),
                    'current' => $session->is_current,
                ];
            });

        return response()->json([
            'success' => true,
            'sessions' => $sessions,
        ]);
    }

    public function destroy(Request $request, $id)
    {
        $user = $request->user();

        $session = Session::findOrFail($id);

        // Make sure the session belongs to the authenticated user
        if ($session->user_id !== $user->id) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized.',
            ], 403);
        }

        // Make sure it's not the current session
        if ($session->is_current) {
            return response()->json([
                'success' => false,
                'message' => 'Cannot terminate current session.',
            ], 400);
        }

        $session->delete();

        return response()->json([
            'success' => true,
            'message' => 'Session has been terminated.',
        ]);
    }

    public function destroyAll(Request $request)
    {
        $user = $request->user();

        // Delete all sessions except the current one
        Session::where('user_id', $user->id)
            ->where('is_current', false)
            ->delete();

        // Also revoke all tokens except the current one
        $user->tokens()
            ->where('id', '!=', $user->currentAccessToken()->id)
            ->delete();

        return response()->json([
            'success' => true,
            'message' => 'All other sessions have been terminated.',
        ]);
    }
}
