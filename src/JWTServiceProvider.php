<?php

namespace Fuatogur\LaravelJWT;

use Illuminate\Support\ServiceProvider;

class JWTServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->app['auth']->extend('jwt', function ($app, $name, $config) {
            return new JwtGuard(
                $name,
                $app['auth']->createUserProvider($config['provider']),
                $app['request'],
                $app['events'],
                $app['config']['app.key']
            );
        });
    }
}