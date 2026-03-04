<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Auth;

use Selivery\Enterprise\Models\AuthTokens;

interface TokenRefresher
{
    public function refresh(string $accessToken, string $refreshToken): AuthTokens;
}
