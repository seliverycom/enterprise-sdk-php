<?php

declare(strict_types=1);

namespace Selivery\Enterprise\Exceptions;

use RuntimeException;

final class ApiException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly int $statusCode = 0,
        public readonly ?string $responseBody = null
    ) {
        parent::__construct($message, $statusCode);
    }
}
