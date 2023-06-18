<?php

declare(strict_types=1);

/**
 * This file is part of mfuns/hyperf-auth.
 *
 * @link     https://www.mfuns.cn
 * @author   ChenDoXiu<chendoxiu@gmail.com>,LixWorth<lixworth@outlook.com>
 * @license  https://github.com/mfuns-cn/hyperf-auth/blob/master/LICENSE
 */

namespace Mfuns\HyperfAuth;

class Utils
{
    /**
     * 获取当前设备ip.
     * @param $request
     * @return string
     */
    public static function ip($request): string
    {
        $headers = $request->getHeaders();
        if (isset($headers['x-forwarded-for'][0]) && ! empty($headers['x-forwarded-for'][0])) {
            return $headers['x-forwarded-for'][0];
        }
        if (isset($headers['x-real-ip'][0]) && ! empty($headers['x-real-ip'][0])) {
            return $headers['x-real-ip'][0];
        }

        $serverParams = $request->getServerParams();
        return $serverParams['remote_addr'] ?? '';
    }

    /**
     * 判断系统平台.
     * @param $request
     * @return string
     */
    public static function equipmentSystem($request): string
    {
        $agent = self::getUserAgent($request);
        if (stristr($agent, 'iPad')) {
            $fb_fs = 'iPad';
        } elseif (preg_match('/Android (([0-9_.]{1,3})+)/i', $agent, $version)) {
            $fb_fs = 'Android ' . $version[1];
        } elseif (stristr($agent, 'Linux')) {
            $fb_fs = 'Linux';
        } elseif (preg_match('/iPhone OS (([0-9_.]{1,3})+)/i', $agent, $version)) {
            $fb_fs = 'iPhone ' . $version[1];
        } elseif (preg_match('/Mac OS X (([0-9_.]{1,5})+)/i', $agent, $version)) {
            $fb_fs = 'OS X ' . $version[1];
        } elseif (preg_match('/unix/i', $agent)) {
            $fb_fs = 'Unix';
        } elseif (preg_match('/windows/i', $agent)) {
            $fb_fs = 'Windows';
        } else {
            $fb_fs = 'Unknown';
        }
        return $fb_fs;
    }

    public static function getUserAgent($request)
    {
        return $request->getHeader('User-Agent')[0] ?? '';
    }
}
