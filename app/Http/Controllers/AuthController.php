<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\Routing\Route;

class AuthController extends Controller
{
    public function index(){
        return view('auth.login');
    }

    /**
     * Handle an authentication attempt.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request){
        $credentials = $request->validate([
            'username' => ['required', 'max:5', 'regex:/^([0-9\s\-\+\(\)]*)$/'],
            'password' => ['required'],
        ]);

 
        if (Auth::attempt($credentials)) {
            $request->session()->regenerate();
 
            return redirect()->intended('home');
        }
 
        return back()->withErrors([
            'email' => 'The provided credentials do not match our records.',
        ])->onlyInput('email');
    }

    /**
     * Log the user out of the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
    */
    public function logout(Request $request){
        Auth::logout();
 
        $request->session()->invalidate();
    
        $request->session()->regenerateToken();
    
        return redirect('/login');
    }

    public function show(){
        return view('auth.register');
    }

    public function register(Request $request){
        $data = $request->validate([
            'name' => ['required'],
            'username' => ['required', 'max:5', 'regex:/^([0-9\s\-\+\(\)]*)$/'],
            'password' => ['required'],
        ]);

        $data['password'] = bcrypt($data['password']);

        User::create($data);

        return redirect('/login');
    }
}
