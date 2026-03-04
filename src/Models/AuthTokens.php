<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Models;

final class AuthTokens
{
    public function __construct(
        public readonly string $accessToken,
        public readonly string $refreshToken,
        public readonly int $sessionTtl,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            accessToken: (string) ($data['access_token'] ?? ''),
            refreshToken: (string) ($data['refresh_token'] ?? ''),
            sessionTtl: (int) ($data['session_ttl'] ?? 0),
        );
    }
}

