![motikan2010/ua-parser-php workflow](https://github.com/motikan2010/ua-parser-php/actions/workflows/main.yml/badge.svg)

# ua-parser-php

## About

PHP UA Parser library based on [https://github.com/faisalman/ua-parser-js](https://github.com/faisalman/ua-parser-js)

## Installation


```
composer require motikan2010/ua-parser-php
```

## Usage

```php
<?php

$parser = new \Motikan2010\UAParser\UAParser();

$uastring1 = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.2 (KHTML, like Gecko) Ubuntu/11.10 Chromium/15.0.874.106 Chrome/15.0.874.106 Safari/535.2';
$parser->setUa($uastring1);
$result = $parser->getResult();

var_export($result);
/*
array (
    'ua' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.2 (KHTML, like Gecko) Ubuntu/11.10 Chromium/15.0.874.106 Chrome/15.0.874.106 Safari/535.2',
    'browser' =>
        array (
            'name' => 'Chromium',
            'version' => '15.0.874.106',
            'major' => '15'
        )
    'engine' =>
        array (
            'name' => 'WebKit',
            'version' => '535.2'
        )
    'os' =>
        array (
            'name' => 'Ubuntu',
            'version' => '11.10'
        ),
    'device' =>
        array (
            'vendor' => NULL,
            'model' => NULL,
            'type' => NULL
        )
    'cpu' =>
        array (
            'architecture' => 'amd64'
        )
)
*/

var_export($result['browser']);             # array ('name' => 'Chromium', 'version' => '15.0.874.106', 'major' => '15')
var_export($result['device']);              # array ('vendor' => NULL, 'model' => NULL, 'type' => NULL)
var_export($result['os']);                  # array ('name' => 'Ubuntu', 'version' => '11.10')
var_export($result['os']['version']);       # '11.10'
var_export($result['engine']['name']);      # 'WebKit'
var_export($result['cpu']['architecture']); # 'amd64'

$uastring2 = "Mozilla/5.0 (compatible; Konqueror/4.1; OpenBSD) KHTML/4.1.4 (like Gecko)";
var_export($parser->setUA($uastring2)->getBrowser()['name']);   # 'Konqueror'
var_export($parser->getOS());       # array ('name' => 'OpenBSD', 'version' => NULL)
var_export($parser->getEngine());   # array ('name' => 'KHTML', 'version' => '4.1.4')

$uastring3 = 'Mozilla/5.0 (PlayBook; U; RIM Tablet OS 1.0.0; en-US) AppleWebKit/534.11 (KHTML, like Gecko) Version/7.1.0.7 Safari/534.11';
var_export($parser->setUA($uastring3)->getDevice()['model']);   # 'PlayBook'
var_export($parser->getOS());               # array ('name' => 'RIM Tablet OS', 'version' => '1.0.0')
var_export($parser->getBrowser()['name']);  # 'Safari'
```

## Test

```
./vendor/bin/phpunit
```
