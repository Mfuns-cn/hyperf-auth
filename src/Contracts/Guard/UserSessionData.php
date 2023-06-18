<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\HyperfAuth\Contracts\Guard;

use Mfuns\HyperfAuth\Contracts\HashTokenData;
use Mfuns\HyperfAuth\Contracts\IdentifierInfo;
use Mfuns\HyperfAuth\Exceptions\UserSessionDataCreateException;

class UserSessionData
{
    public function __construct(
        private HashTokenData $hashTokenData,
        private string|int $expire_time,
        private string $active_ip,
        private string|int $login_time,
        private string|int $active_time,
        private array $extra
    ) {
    }

    /**
     * 从 json 或者 数组里解析用户会话数据.
     * @throws UserSessionDataCreateException
     */
    public static function factory(array|string $data): self
    {
        if (is_string($data)) {
            $data = json_decode($data, true);
        }

        // check data
        foreach (['hash_token_data', 'expire_time', 'active_ip', 'login_time', 'active_time', 'extra'] as $item) {
            if (! isset($data[$item])) {
                throw new UserSessionDataCreateException('err 1');
            }
        }

        if (! is_array($data['extra'])) {
            throw new UserSessionDataCreateException('err 2');
        }
        if (! isset($data['hash_token_data'])
            || ! isset($data['hash_token_data']['identifier_info'])
            || ! isset($data['hash_token_data']['session_id'])
            || ! isset($data['hash_token_data']['identifier_info']['name'])
            || ! isset($data['hash_token_data']['identifier_info']['value'])
        ) {
            throw new UserSessionDataCreateException('err 3');
        }
        return new self(
            new HashTokenData(
                (new IdentifierInfo(
                    $data['hash_token_data']['identifier_info']['name'],
                    $data['hash_token_data']['identifier_info']['value']
                ))->toArray(),
                $data['hash_token_data']['session_id']
            ),
            $data['expire_time'],
            $data['active_ip'],
            $data['login_time'],
            $data['active_time'],
            $data['extra']
        );
    }

    public function toArray(): array
    {
        return [
            'hash_token_data' => [
                'identifier_info' => [
                    'name' => $this->hashTokenData->getIdentifierInfo()->getName(),
                    'value' => $this->hashTokenData->getIdentifierInfo()->getValue(),
                ],
                'session_id' => $this->hashTokenData->getSessionId(),
            ],
            'expire_time' => $this->expire_time,
            'active_ip' => $this->active_ip,
            'login_time' => $this->login_time,
            'active_time' => $this->active_time,
            'extra' => $this->extra,
        ];
    }

    public function updateExpireTime(string|int $time): self
    {
        $this->expire_time = $time;
        return $this;
    }

    public function updateActiveTime(): self
    {
        $this->active_time = time();
        return $this;
    }

    public function updateActiveIP($ip): self
    {
        $this->active_ip = $ip;
        return $this;
    }

    /**
     * @return string
     */
    public function getActiveIp(): string
    {
        return $this->active_ip;
    }

    /**
     * @return int
     */
    public function getActiveTime(): int
    {
        return (int) $this->active_time;
    }

    /**
     * @return int
     */
    public function getExpireTime(): int
    {
        return (int) $this->expire_time;
    }

    /**
     * @return array
     */
    public function getExtra(): array
    {
        return $this->extra;
    }

    public function setExtra(array $extra): self
    {
        $this->extra = $extra;
        return $this;
    }

    /**
     * @return int
     */
    public function getLoginTime(): int
    {
        return (int) $this->login_time;
    }

    /**
     * @return HashTokenData
     */
    public function getHashToken(): HashTokenData
    {
        return $this->hashTokenData;
    }
}
