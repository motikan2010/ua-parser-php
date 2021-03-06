<?php

namespace Motikan2010\UAParser;

class Mapper
{
    /**
     * @var Util
     */
    private $util;

    /**
     * Mapper constructor.
     */
    public function __construct()
    {
        $this->util = new Util();
    }

    /**
     * @param $rItem
     * @param $ua
     * @param $arrays
     */
    public function rgx(&$rItem, $ua, $arrays)
    {
        $i = 0;

        $matches = false;

        while ($i < count($arrays) && !$matches) {
            $regex = $arrays[$i];
            $props = $arrays[$i + 1];
            $j = $k = 0;

            while ($j < count($regex) && !$matches) {
                preg_match($regex[$j++], $ua, $matches);

                if ($matches) {
                    for ($p = 0; $p < count($props); $p++) {
                        ++$k;
                        $match = isset($matches[$k]) ? $matches[$k] : null;
                        $q = $props[$p];

                        if (is_array($q)) {
                            if (count($q) == 2) {
                                if (is_callable($q[1])) {
                                    $rItem[$q[0]] = $q[1]($match);
                                } else {
                                    $rItem[$q[0]] = $q[1];
                                }
                            } elseif (count($q) == 3) {
                                if (is_callable($q[1]) && !$this->isRegularExpression($q[1])) {
                                    $rItem[$q[0]] = ($match) ? $q[1]($match, $q[2]) : null;
                                } else {
                                    $rItem[$q[0]] = ($match) ? preg_replace($q[1], $q[2], $match) : null;
                                }
                            } elseif (count($q) == 4) {
                                $rItem[$q[0]] = $match ? $q[3](preg_replace($q[1], $q[2], $match)) : null;
                            }
                        } else {
                            $rItem[$q] = $match ? $match : null;
                        }
                    }
                }
            }
            $i += 2;
        }
    }

    /**
     * @param $str
     * @param $map
     * @return int|null|string
     */
    public function str($str, $map)
    {
        foreach ($map as $key => $item) {
            if (is_array($item) && count($item) > 0) {
                for ($j = 0; $j < count($item); $j++) {
                    if ($this->util->has($item[$j], $str)) {
                        return ($key === UAParser::UNKNOWN) ? null : $key;
                    }
                }
            } elseif ($this->util->has($item, $str)) {
                return ($key === UAParser::UNKNOWN) ? null : $key;
            }
        }
        return $str;
    }

    /**
     * @param $string
     * @return bool
     */
    protected function isRegularExpression($string)
    {
        set_error_handler(function () {
        }, E_WARNING);
        $isRegularExpression = preg_match($string, "") !== FALSE;
        restore_error_handler();
        return $isRegularExpression;
    }

}