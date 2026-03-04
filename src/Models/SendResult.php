<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Models;

final class SendResult
{
    public function __construct(
        public readonly string $messageUuid,
        public readonly bool $success,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            messageUuid: (string) ($data['message_uuid'] ?? ''),
            success: (bool) ($data['success'] ?? false),
        );
    }
}

