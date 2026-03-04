<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Models;

final class PublicKey
{
    public function __construct(
        public readonly string $device,
        public readonly string $publicKey,
        public readonly string $uuid,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            device: (string) ($data['device'] ?? ''),
            publicKey: (string) ($data['publicKey'] ?? ''),
            uuid: (string) ($data['uuid'] ?? ''),
        );
    }
}

