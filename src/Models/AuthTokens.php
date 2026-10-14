<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Models;

final class AuthTokens
{
    public function __construct(
        public readonly string $accessToken,
        public readonly string $refreshToken,
        public readonly int $sessionTtl,
    ) {
        if (trim($accessToken) === '') {
            throw new \InvalidArgumentException('Authentication response must contain a non-empty access_token string.');
        }
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        if (!isset($data['access_token']) || !is_string($data['access_token'])) {
            throw new \InvalidArgumentException('Authentication response must contain a non-empty access_token string.');
        }

        return new self(
            accessToken: $data['access_token'],
            refreshToken: is_string($data['refresh_token'] ?? null) ? $data['refresh_token'] : '',
            sessionTtl: is_numeric($data['session_ttl'] ?? null) ? (int) $data['session_ttl'] : 0,
        );
    }
}
