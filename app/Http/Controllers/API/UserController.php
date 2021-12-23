<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller
{
    public function register(Request $request)
    {
        try{
            $request->validate([
                'name' => ['required', 'string', 'max:255'],
                'username' => ['required', 'string', 'max:255', 'unique:users'],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'phone' => ['nullable', 'string', 'max:255'],
                'password' => ['required', 'string', new Password],
            ]);
            
            User::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone,
                'password' => Hash::make($request->password),
            ]);

            $user = User::where('email', $request->email)->first();

            $tokenResult = $user->createToken('authToken')->plainTextToken; 

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'User Registered');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentification_Failed', 500);
        }
    }

    public function login(Request $request)
    {
        try {
            $request->validate([
                'email' => 'emailrequired',
                'password' => 'required'
            ]);

            //kalau gagal
            $credentials  = request(['email', 'password']);
            if (!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'
                ], 'Authentification Failed', 500);
            }

            //kalau berhasil masuk kesini 
            $user = User::where('email', $request->email)->first();
            if (! Hash::check($request->password, $user->passsword, [])){
                throw new \Exception('Invalid Credentials');
            }

             $tokenResult = $user->createToken('authToken')->plainTextToken;
             return ResponseFormatter::success([
                 'accsess_token' => $tokenResult,
                 'token_type' => 'Bearer',
                 'user' => $user
             ], 'Authenticated');
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentification haha Failed', 500);
        }
    }

    public function fetch (Request $request)
    {
        return ResponseFormatter::success($request->user(), 'Data profile user berhasil diambil');
    }

    public function updateProfile(Request $request) 
    {
        $data = $request->all(); //menyimpan data

        $user = Auth::user(); //untuk mengambil data user yang sedang login
        $user->update($data);

        return ResponseFormatter::success($user,'Profile updated');
    }

    public function logout(Request $request)
    {
         $token = $request->user()->currentAccessToken()->delete(); 

         return ResponseFormatter::success($token, 'Token Revoked');
    }
}