<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\ProductController;
use Illuminate\Support\Facades\Route;


/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});


Route::controller(AuthController::class)->group(function () {
    Route::get('/login', 'index')->name('login');
    Route::post('/create', 'store');
    Route::get('/logout', 'logout');
    Route::get('/register', 'show')->name('register');
    Route::post('/create-register', 'register');
});

Route::middleware(['auth'])->group(function () {
    Route::get('/product-list', [ProductController::class, 'index']);
});