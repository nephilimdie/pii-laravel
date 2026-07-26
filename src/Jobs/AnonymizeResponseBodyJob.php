<?php

declare(strict_types=1);

namespace PiiProtect\Laravel\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use PiiProtect\Laravel\Events\ResponseBodyAnonymized;
use PiiProtect\Laravel\PiiProtectClient;

class AnonymizeResponseBodyJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(
        private readonly array $data,
        private readonly array $skipKeys,
    ) {}

    public function handle(PiiProtectClient $client): void
    {
        $sanitized = $client->anonymizeArray($this->data, $this->skipKeys);
        event(new ResponseBodyAnonymized($sanitized));
    }
}
