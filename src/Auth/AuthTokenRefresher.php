<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Auth;

use Selivery\Enterprise\Models\AuthTokens;

final class AuthTokenRefresher implements TokenRefresher
{
    public function __construct(private readonly \Selivery\Enterprise\Auth\AuthClient $authClient) {}

    public function refresh(string $accessToken, string $refreshToken): AuthTokens
    {
        return $this->authClient->refreshToken($accessToken, $refreshToken);
    }
}
