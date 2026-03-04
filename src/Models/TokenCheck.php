<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Models;

final class TokenCheck
{
    public function __construct(
        public readonly string $message,
        public readonly bool $success,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            message: (string) ($data['message'] ?? ''),
            success: (bool) ($data['success'] ?? false),
        );
    }
}

