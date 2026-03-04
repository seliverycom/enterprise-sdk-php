<?php

declare(strict_types=1);

namespace Selivery\Enterprise;

final class Config
{
    public function __construct(
        public string $baseUrl = 'https://enterprise-api.selivery.com',
        public ?string $secret = null,
        public float $timeout = 10.0
    ) {}
}
