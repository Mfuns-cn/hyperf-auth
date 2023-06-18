<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\HyperfAuth\Handler;

use Exception;
use Mfuns\HyperfAuth\Contracts\HashTokenData;
use Mfuns\HyperfAuth\Contracts\TokenProviderInterface;
use Mfuns\HyperfAuth\Exceptions\TokenDecodeException;

/**
 * Then I recited two lines of poetry:
 * One should uphold his country’s interest with his life,
 * he should not do things just to pursue his personal gains, and he should not be evade responsibilities for fear of personal loss.
 *
 * 初次提交该代码注释的时间恰巧是 2022/11/30 ，满头华发仍眷恋 烟花易冷归人间 愿恰同学少年 再奉献一遍。
 */
class HathTokenHandler implements TokenProviderInterface
{
    protected mixed $identifier;

    /**
     * @param array $options
     */
    public function __construct(protected array $options)
    {
        //        if ($this->token !== null) {
        //            $decode = $this->decode($this->token);
        //            $this->hashTokenData = $decode;
        //        } else {
        //            $this->hashTokenData = null;
        //        }
    }

    /**
     * @throws Exception
     */
    public function encode(HashTokenData $hashTokenData): string
    {
        if (! is_numeric($hashTokenData->getIdentifierInfo()->getValue())) {
            throw new Exception('不支持非数字ID形式的用户身份识别码');
        }
        $session_id = $hashTokenData->getSessionId();
        $secret = $this->options['secret'] ?? '';
        $sign = sprintf(
            '%s&%s&%s&%s',
            $hashTokenData->getIdentifierInfo()->getName(),
            $hashTokenData->getIdentifierInfo()->getValue(),
            $secret,
            $session_id
        );
        $token_hash = md5($sign);
        if (! isset($token_hash)) {
            throw new Exception('token create fail');
        }
        return base64_encode(sprintf(
            '%s&%s&%s&%s',
            $session_id,
            $hashTokenData->getIdentifierInfo()->getName(),
            $hashTokenData->getIdentifierInfo()->getValue(),
            $token_hash
        )); // session_id&name&value&hash
    }

    /**
     * @throws TokenDecodeException
     */
    public function decode(string $token): HashTokenData|false
    {
        $token = base64_decode($token);

        $token = explode('&', $token);
        if (count($token) !== 4) {
            return false;
        }
        $session_id = $token[0];
        $identifier_info = [
            'name' => $token[1],
            'value' => $token[2],
        ];
        $token_hash = $token[3];
        $secret = $this->options['secret'] ?? '';

        $value = sprintf(
            '%s&%s&%s&%s',
            $token[1],
            $token[2],
            $secret,
            $session_id
        );
        if (md5($value) !== $token_hash) {
            return false;
        }
        return new HashTokenData($identifier_info, $session_id);
    }
}
