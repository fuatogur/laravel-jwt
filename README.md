# LARAVEL JWT

JWT Authentication for Laravel

## Why
There are good laravel jwt packages but i saw them as complex and created this package.
## Installation
1. Firstly install the package via composer
```
composer require fuatogur/laravel-jwt
```
2. Set your auth guard as `jwt`

## Usage
1. Add getJWTData method to your User class to specify which data should be included in jwt token
```php
class User extends Model
{
    public function getJWTData()
    {
        return [
            'id' => $this->id,
            'email' => $this->email
        ]
    }
}
```
2. Use `Auth::token()` to get the token for the user
