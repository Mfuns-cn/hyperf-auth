<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\HyperfAuth\Contracts;

/**
 * 存储在 token 内的信息.
 */
class HashTokenData
{
    protected IdentifierInfo $identifier_info;

    protected string $session_id;

    public function __construct($identifier_info, $session_id)
    {
        $this->identifier_info = new IdentifierInfo($identifier_info['name'], $identifier_info['value']);
        $this->session_id = $session_id;
    }

    /**
     * @return IdentifierInfo
     */
    public function getIdentifierInfo(): IdentifierInfo
    {
        return $this->identifier_info;
    }

    /**
     * @return string
     */
    public function getSessionId(): string
    {
        return $this->session_id;
    }
}
