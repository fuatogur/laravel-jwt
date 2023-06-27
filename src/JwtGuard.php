<?php

namespace Fuatogur\LaravelJWT;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use LogicException;
use UnexpectedValueException;

class JwtGuard implements Guard
{
    use GuardHelpers;

    /**
     * Name of the guard.
     *
     * @var string
     */
    protected $name;

    /**
     * The user we last attempted to retrieve.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    protected $lastAttempted;

    /**
     * Request.
     *
     * @var Request
     */
    protected $request;

    /**
     * Event dispatcher.
     *
     * @var Dispatcher
     */
    protected $events;

    /**
     * App key.
     *
     * @var string
     */
    protected $key;

    public function __construct($name, $provider, $request, $events, $key)
    {
        $this->name = $name;
        $this->provider = $provider;
        $this->request = $request;
        $this->events = $events;
        $this->key = $key;
    }

    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        $token = $this->request->bearerToken();
        if (!$token) {
            $token = $this->request->input('Token');
        }

        if ($token) {
            try {
                $decoded = JWT::decode($token, new Key($this->key, 'HS256'));
            } catch (UnexpectedValueException|LogicException $exception) {
                return null;
            }

            $id = $decoded->id;

            $this->user = $this->provider->retrieveById($id);

            if (!is_null($this->user)) {
                $this->events->dispatch(new Login($this->name, $this->user, false));
            }
        }

        return $this->user;
    }

    public function token()
    {
        if (is_null($user = $this->user())) {
            return null;
        }

        return JWT::encode($user->getJWTData(), $this->key, 'HS256');
    }

    public function getToken()
    {
        return $this->token();
    }

    public function attempt(array $credentials = [])
    {
        $this->events->dispatch(new Attempting(
            $this->name, $credentials, false
        ));

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user);

            return true;
        }

        $this->events->dispatch(new Failed(
            $this->name, $user, $credentials
        ));

        return false;
    }

    public function validate(array $credentials = [])
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        return $this->hasValidCredentials($user, $credentials);
    }

    protected function hasValidCredentials($user, $credentials)
    {
        $validated = !is_null($user) && $this->provider->validateCredentials($user, $credentials);

        if ($validated) {
            $this->events->dispatch(new Validated(
                $this->name, $user
            ));
        }

        return $validated;
    }

    public function loginUsingId($id)
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user);

            return $user;
        }

        return false;
    }

    public function login(Authenticatable $user)
    {
        $this->events->dispatch(new Login(
            $this->name, $user, false
        ));

        $this->setUser($user);
    }

    public function setUser(Authenticatable $user)
    {
        $this->events->dispatch(new Authenticated($this->name, $user));

        $this->user = $user;

        return $this;
    }
}
