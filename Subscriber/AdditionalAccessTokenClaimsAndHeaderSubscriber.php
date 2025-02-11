<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\Subscriber;

use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTCreatedEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Events;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Clock\ClockAwareTrait;

final class AdditionalAccessTokenClaimsAndHeaderSubscriber implements EventSubscriberInterface
{
    use ClockAwareTrait;

    /**
     * @var int|null
     */
    private $ttl;

    public function __construct(?int $ttl)
    {
        $this->ttl = $ttl;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            Events::JWT_CREATED => [
                ['addClaims'],
            ],
        ];
    }

    public function addClaims(JWTCreatedEvent $event): void
    {
        $claims = [
            'jti' => uniqid('', true),
            'iat' => $this->now()->getTimestamp(),
            'nbf' => $this->now()->getTimestamp(),
        ];
        $data = $event->getData();
        if (!array_key_exists('exp', $data) && $this->ttl > 0) {
            $claims['exp'] = $this->now()->getTimestamp() + $this->ttl;
        }
        $event->setData(array_merge($claims, $data));
    }
}
