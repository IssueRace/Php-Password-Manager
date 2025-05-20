<?php
class PasswordGenerator {
    public function generate($length, $useLower = true, $useUpper = true, $useDigits = true, $useSpecial = true) {
        $lower = 'abcdefghijklmnopqrstuvwxyz';
        $upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $digits = '0123456789';
        $special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        $chars = '';

        if ($useLower) $chars .= $lower;
        if ($useUpper) $chars .= $upper;
        if ($useDigits) $chars .= $digits;
        if ($useSpecial) $chars .= $special;

        if (empty($chars)) {
            throw new Exception("At least one character set must be selected.");
        }

        $password = '';
        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, strlen($chars) - 1)];
        }

        return $password;
    }
}
?>